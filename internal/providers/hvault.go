/*
Hashicorp Vault iteration of the PKCS11 interface from KMSv2 mockup example
Author: rom@beezy.dev
Apache 2.0 License
*/
package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	//"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
	"go.uber.org/zap"
	"k8s.io/kms/pkg/service"
)

var _ service.Service = &hvaultRemoteService{}

type hvaultRemoteService struct {
	*api.Client

	UnixSock    string
	LatestKeyID string
	// keyID      string
	Debug      bool
	Namespace  string `json:"namespace"`
	Transitkey string `json:"transitkey"`
	Vaultrole  string `json:"vaultrole"`
	Address    string `json:"address"`
}

func NewVaultClientRemoteService(configFilePath string, addr string, debug bool) (service.Service, error) {
	ctx, err := os.ReadFile(configFilePath)
	if err != nil {
		zap.L().Fatal("EXIT:ctx: failed to read vault config file with error: " + err.Error())
	}
	if len(keyID) == 0 {
		zap.L().Fatal("EXIT:keyID len: invalid keyID")
	}

	// vaultService := &hvaultRemoteService{
	// 	// keyID: keyID,
	// 	Debug: debug,
	// }

	vaultService := &hvaultRemoteService{}
	vaultService.Debug = debug
	vaultService.UnixSock = addr
	json.Unmarshal(([]byte(ctx)), &vaultService)

	vaultconfig := api.DefaultConfig()
	vaultconfig.Address = vaultService.Address

	zap.L().Debug("Config loaded:", zap.String("Vault address", vaultService.Address),
		zap.String("Transit key name", vaultService.Transitkey),
		zap.String("Vault role", vaultService.Vaultrole),
		zap.String("Vault namespace", vaultService.Vaultrole))
	client, err := api.NewClient(vaultconfig)
	if err != nil {
		zap.L().Fatal("EXIT:client: failed to initialize Vault client with error: " + err.Error())
	}

	k8sAuth, err := auth.NewKubernetesAuth(
		vaultService.Vaultrole,
	)

	if err != nil {
		zap.L().Fatal("EXIT:k8sAuth: unable to initialize Kubernetes auth method with error: " + err.Error())
	}

	authInfo, err := client.Auth().Login(context.Background(), k8sAuth)
	if err != nil {
		zap.L().Fatal("EXIT:authInfo: unable to log in with Kubernetes auth with error: " + err.Error())
	}
	if authInfo == nil {
		zap.L().Fatal("EXIT:authInfo: no kubernetes auth info was returned after login")
	}

	// vaultService = &hvaultRemoteService{
	// 	Client: client,
	// }
	vaultService.Client = client

	client.SetNamespace(vaultService.Namespace)

	// obtain latest version of the transit key and create a key ID for it
	key, err := vaultService.GetTransitKey(context.Background())
	if err != nil {
		zap.L().Fatal("ERROR:key: unable to find transit key, shutting down: " + err.Error())
	}
	vaultService.LatestKeyID = createLatestTransitKeyId(key)

	zap.L().Info("Received key ID on startup: " + vaultService.LatestKeyID)

	// initial token check - it can happen that k8s restarted ??
	err = vaultService.CheckTokenValidity(context.Background())
	if err != nil {
		// will call GetVaultToken and that already handles Fatal..
		zap.L().Fatal("EXIT:token: could not check token validity: " + err.Error())
	}

	return vaultService, nil
}

func (s *hvaultRemoteService) Encrypt(ctx context.Context, uid string, plaintext []byte) (*service.EncryptResponse, error) {
	enckeypath := fmt.Sprintf("transit/encrypt/%s", s.Transitkey)
	encodepayload := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}

	encrypt, err := s.Logical().WriteWithContext(ctx, enckeypath, encodepayload)
	if err != nil {
		zap.L().Debug("encrypt:plaintext: " + string([]byte(plaintext)) +
			" keypath: " + enckeypath + "\nencodepayload: " + fmt.Sprintf("%v", encodepayload))
		// remove fatal, return error
		zap.L().Fatal("EXIT:encrypt: with error: " + err.Error())
	}
	enresult, ok := encrypt.Data["ciphertext"].(string)
	if !ok {
		zap.L().Debug("enresult: " + string([]byte(enresult)))
		// remove fatal, return error
		zap.L().Fatal("EXIT:enresult: invalid response")
	}

	return &service.EncryptResponse{
		Ciphertext: []byte(enresult),
		KeyID:      s.LatestKeyID,
		Annotations: map[string][]byte{
			annotationKey: []byte("1"),
		},
	}, nil
}

func (s *hvaultRemoteService) Decrypt(ctx context.Context, uid string, req *service.DecryptRequest) ([]byte, error) {

	if len(req.Annotations) != 1 {
		zap.L().Error("len:annotations: " + fmt.Sprintf("%v", req.Annotations))
		return nil, fmt.Errorf("/!\\ invalid annotations")
	}
	if v, ok := req.Annotations[annotationKey]; !ok || string(v) != "1" {
		return nil, fmt.Errorf("/!\\ invalid version in annotations")
	}
	// if req.KeyID != s.LatestKeyID {
	// 	return nil, fmt.Errorf("/!\\ invalid keyID")
	// }

	decryptkeypath := fmt.Sprintf("transit/decrypt/%s", s.Transitkey)

	encryptedPayload := map[string]interface{}{
		"ciphertext": string([]byte(req.Ciphertext)),
	}

	encryptedResponse, err := s.Logical().WriteWithContext(ctx, decryptkeypath, encryptedPayload)
	if err != nil {
		// remove fatal, return error
		zap.L().Fatal("EXIT:encryptedResponse: with error: " + err.Error())
	}

	response, ok := encryptedResponse.Data["plaintext"].(string)
	if !ok {
		// remove fatal, return error
		zap.L().Fatal("EXIT:response: invalid response")
	}

	decodepayload, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		// remove fatal, return error
		zap.L().Fatal("EXIT:decodepayload: with error: " + err.Error())
	}

	return decodepayload, nil

}

func (s *hvaultRemoteService) Status(ctx context.Context) (*service.StatusResponse, error) {
	// check if unix socket is still present
	if _, err := os.Stat(s.UnixSock); errors.Is(err, os.ErrNotExist) {
		zap.L().Fatal("EXIT:status: socket removed: " + err.Error())
	}

	// get transit key, obtain the latest version of the transit key
	key, err := s.GetTransitKey(ctx)
	if err != nil {
		// fatal if permission error (handled in GetTransitKey)
		zap.L().Error("ERROR:key: unable to find transit key: " + err.Error())
		return s.createStatusResponse(healthNOK), err
	}

	// extract the latest and create key id for it
	oldKeyID := s.LatestKeyID
	s.LatestKeyID = createLatestTransitKeyId(key)
	if s.LatestKeyID != oldKeyID {
		zap.L().Info("Key ID updated to: " + s.LatestKeyID)
	} else {
		zap.L().Info("Key ID is already the latest.")
	}

	// do healthcheck
	err = s.Health(ctx)
	if err != nil {
		zap.L().Error("ERROR:Status: unhealthy: " + err.Error())
		return s.createStatusResponse(healthNOK), err
	}

	return s.createStatusResponse(healthOK), nil
}

func (s *hvaultRemoteService) Health(ctx context.Context) error {
	// check if it has valid token lease (Vault)
	err := s.CheckTokenValidity(ctx)
	if err != nil {
		return errors.New("Health:token: token validity check failed: " + err.Error())
	}
	// check encrypt/decrypt if operation can be performed correctly
	enc, err := s.Encrypt(ctx, fmt.Sprintf("health-enc-%s", strconv.FormatInt(time.Now().Unix(), 10)), []byte(healthy))
	if err != nil {
		return errors.New("Health: encrypt failed: " + err.Error())
	}

	dec, err := s.Decrypt(ctx, fmt.Sprintf("health-dec-%s", strconv.FormatInt(time.Now().Unix(), 10)), &service.DecryptRequest{
		Ciphertext: enc.Ciphertext,
		KeyID:      s.LatestKeyID,
		Annotations: map[string][]byte{
			annotationKey: []byte("1"),
		},
	})

	if err != nil {
		//zap.L().Error("ERROR:Health: decrypt failed: " + err.Error())
		return errors.New("Health: decrypt failed: " + err.Error())
	}

	// decrypted plaintext does not match
	if healthy != string(dec) {
		return errors.New("Health check failed: decrypt does not match")
	}

	zap.L().Info("Health check OK")

	return nil
}

func (s *hvaultRemoteService) createStatusResponse(healthz string) *service.StatusResponse {
	// creates status response ok/nok with latest key ID
	return &service.StatusResponse{
		Version: "v2",
		Healthz: healthz,
		KeyID:   s.LatestKeyID,
	}
}

func (s *hvaultRemoteService) GetTransitKey(ctx context.Context) (*api.Secret, error) {
	key, err := s.Client.Logical().ReadWithContext(ctx, fmt.Sprintf("transit/keys/%s", s.Transitkey))
	if err != nil {
		// no transit key or no token
		if strings.Contains(err.Error(), "invalid token") {
			zap.L().Fatal("EXIT:token: invalid token, restarting: " + err.Error())
		}
		return nil, err
	}
	zap.L().Debug("Transit key: " + fmt.Sprintf("%v", map[string]interface{}{
		"latest_version":         key.Data["latest_version"],
		"min_available_version":  key.Data["min_available_version"],
		"min_encryption_version": key.Data["min_encryption_version"],
		"min_decryption_version": key.Data["min_decryption_version"],
		"auto_rotate_period":     key.Data["auto_rotate_period"]}))

	return key, nil
}

func createLatestTransitKeyId(key *api.Secret) string {
	latest_version := fmt.Sprintf("%s", key.Data["latest_version"])
	keys := make(map[string]interface{})
	if a, ok := key.Data["keys"].(map[string]interface{}); ok {
		keys = a
	}
	// key id is concatenated from keyID (constant), field latest_version (a number),
	// field keys[latest_version] which is creation timestamp of that key version
	latest_key_id := fmt.Sprintf("%s_%s_%s", keyID, latest_version, keys[latest_version])
	return latest_key_id
}

func (s *hvaultRemoteService) GetVaultToken(ctx context.Context) (*api.Secret, error) {
	// requires policy to have: "auth/token/lookup-self read and "auth/token/renew-self" update
	path := fmt.Sprintf("auth/token/lookup-self")
	token, err := s.Client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		if strings.Contains(err.Error(), "invalid token") {
			zap.L().Fatal("EXIT:token: invalid token, restarting: " + err.Error())
		}
		return nil, err
	}
	return token, nil
}

func (s *hvaultRemoteService) CheckTokenValidity(ctx context.Context) error {
	token, err := s.GetVaultToken(ctx)
	if err != nil {
		zap.L().Error("Token: could not get token: " + err.Error())
		return err
	}

	creation_ttl, _ := strconv.Atoi(fmt.Sprintf("%s", token.Data["creation_ttl"]))
	ttl, _ := strconv.Atoi(fmt.Sprintf("%s", token.Data["ttl"]))

	zap.L().Debug("Token: " + fmt.Sprintf("%v", map[string]interface{}{
		"creation_ttl":     creation_ttl,
		"issue_time":       token.Data["issue_time"],
		"expire_time":      token.Data["expire_time"],
		"explicit_max_ttl": token.Data["explicit_max_ttl"],
		"ttl":              ttl,
	}))
	if ttl <= 0 || ttl > creation_ttl {
		// token has been tampered with
		// also happens if you've modify role's ttl by hand
		// To wait (return Error) or not to wait (Fatal)?
		zap.L().Fatal("EXIT:token: invalid ttl, re-login needed")
	}
	// update the token if it reached it's validity periods about 2/3rd
	if ttl <= creation_ttl-int(float32(creation_ttl)*0.667) {
		// update the token
		zap.L().Debug("Updating the token.")
		err = s.RenewOwnToken(ctx, creation_ttl)
		if err != nil {
			zap.L().Error("Token update failed: " + err.Error())
			return errors.New("Token update failed.")
		} else {
			zap.L().Info("Token update successful.")
		}
	}
	// no need for token update
	zap.L().Debug("No need for token update.")
	return nil
}

func (s *hvaultRemoteService) RenewOwnToken(ctx context.Context, creation_ttl int) error {
	// renews with the original creation_ttl
	path := fmt.Sprintf("auth/token/renew-self")
	_, err := s.Client.Logical().WriteWithContext(ctx, path, map[string]any{"data": map[string]any{
		"ttl":       fmt.Sprintf("%d", creation_ttl),
		"renewable": "true"}})
	if err != nil {
		// check why the token cannot be renewed
		// if e.g. permission denied -> fatal (token modified, policy changed ..)
		if strings.Contains(err.Error(), "invalid token") {
			zap.L().Fatal("EXIT:token: unable to renew token: " + err.Error())
		}
		return err
	}
	return nil
}
