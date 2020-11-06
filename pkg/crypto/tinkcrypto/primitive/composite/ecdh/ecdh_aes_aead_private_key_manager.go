/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

const (
	ecdhAESPrivateKeyVersion = 0
	ecdhAESPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhAesAeadPrivateKey"
)

// common errors.
var (
	errInvalidECDHAESPrivateKey       = errors.New("ecdh_aes_private_key_manager: invalid key")
	errInvalidECDHAESPrivateKeyFormat = errors.New("ecdh_aes_private_key_manager: invalid key format")
)

// ecdhAESPrivateKeyManager is an implementation of PrivateKeyManager interface.
// It generates new ECDHPrivateKey (AES) keys and produces new instances of ECDHAEADCompositeDecrypt subtle.
type ecdhAESPrivateKeyManager struct{}

// Assert that ecdhAESPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*ecdhAESPrivateKeyManager)(nil)

// newECDHPrivateKeyManager creates a new ecdhAESPrivateKeyManager.
func newECDHPrivateKeyManager() *ecdhAESPrivateKeyManager {
	return new(ecdhAESPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *ecdhAESPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHAESPrivateKey
	}

	key := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidECDHAESPrivateKey
	}

	_, err = km.validateKey(key)
	if err != nil {
		return nil, errInvalidECDHAESPrivateKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(key.PublicKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("ecdh_aes_private_key_manager: NewRegisterCompositeAEADEncHelper "+
			"failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeDecrypt(rEnc, key.PublicKey.Params.EncParams.CEK), nil
}

// NewKey creates a new key according to the specification of ECDHESPrivateKey format.
func (km *ecdhAESPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDHAESPrivateKeyFormat
	}

	keyFormat := new(ecdhpb.EcdhAeadKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidECDHAESPrivateKeyFormat
	}

	curve, err := validateKeyFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidECDHAESPrivateKeyFormat
	}

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, fmt.Errorf("ecdh_aes_private_key_manager: GenerateECDHKeyPair failed: %w", err)
	}

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  ecdhAESPrivateKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: ecdhAESPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of ECDHESPrivateKey Format.
// It should be used solely by the key management API.
func (km *ecdhAESPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_aes_private_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhAESPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *ecdhAESPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidECDHAESPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDHAESPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhAESPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhAESPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhAESPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhAESPrivateKeyManager) TypeURL() string {
	return ecdhAESPrivateKeyTypeURL
}

// validateKey validates the given ECDHPrivateKey and returns the KW curve.
func (km *ecdhAESPrivateKeyManager) validateKey(key *ecdhpb.EcdhAeadPrivateKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, ecdhAESPrivateKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_aes_private_key_manager: invalid key: %w", err)
	}

	return validateKeyFormat(key.PublicKey.Params)
}

// validateKeyFormat validates the given ECDHESKeyFormat and returns the KW Curve.
func validateKeyFormat(params *ecdhpb.EcdhAeadParams) (elliptic.Curve, error) {
	var (
		c   elliptic.Curve
		err error
	)

	// if CEK is set, then curve is unknown, ie this is not a recipient key, it's a primitive execution key for
	// Encryption/Decryption. Set P-384 curve for key generation
	if params.EncParams.CEK == nil {
		c, err = hybrid.GetCurve(params.KwParams.CurveType.String())
		if err != nil {
			return nil, fmt.Errorf("ecdhes_aes_private_key_manager: invalid key: %w", err)
		}
	} else {
		c = elliptic.P384()
	}

	km, err := registry.GetKeyManager(params.EncParams.AeadEnc.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_aes_private_key_manager: GetKeyManager error: %w", err)
	}

	_, err = km.NewKeyData(params.EncParams.AeadEnc.Value)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_aes_private_key_manager: NewKeyData error: %w", err)
	}

	return c, nil
}
