/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

type provider interface {
	VDRegistry() vdr.Registry
	DIDRotator() *didrotate.DIDRotator
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	DIDConnectionStore() didstore.ConnectionStore
}

// Client is a connection management SDK client.
type Client struct {
	didRotator         *didrotate.DIDRotator
	connectionRecorder *connection.Recorder
	didMap             didstore.ConnectionStore
	didResolver        vdr.Registry
}

// New creates connection Client.
func New(prov provider) (*Client, error) {
	connRec, err := connection.NewRecorder(prov)
	if err != nil {
		return nil, err
	}

	return &Client{
		didRotator:         prov.DIDRotator(),
		connectionRecorder: connRec,
		didResolver:        prov.VDRegistry(),
		didMap:             prov.DIDConnectionStore(),
	}, nil
}

// RotateDID rotates the DID of the given connection to the given new DID, using the signing KID for the key in the old
// DID doc to sign the DID rotation.
func (c *Client) RotateDID(connectionID, signingKID, newDID string) error {
	return c.didRotator.RotateConnectionDID(connectionID, signingKID, newDID)
}

// CreateConnectionV2 creates a DIDComm V2 connection with the given DID.
func (c *Client) CreateConnectionV2(myDID, theirDID string, opts ...CreateConnectionOption) (string, error) {
	theirDocRes, err := c.didResolver.Resolve(theirDID)
	if err != nil {
		return "", fmt.Errorf("resolving their DID: %w", err)
	}

	theirDoc := theirDocRes.DIDDocument

	err = c.didMap.SaveDIDFromDoc(theirDoc)
	if err != nil {
		return "", fmt.Errorf("failed to save theirDID to the did.ConnectionStore: %w", err)
	}

	err = c.didMap.SaveDIDByResolving(myDID)
	if err != nil {
		return "", fmt.Errorf("failed to save myDID to the did.ConnectionStore: %w", err)
	}

	destination, err := service.CreateDestination(theirDoc)
	if err != nil {
		return "", fmt.Errorf("failed to create destination: %w", err)
	}

	connID := uuid.New().String()

	connRec := connection.Record{
		ConnectionID:    connID,
		State:           connection.StateNameCompleted,
		TheirDID:        theirDID,
		MyDID:           myDID,
		ServiceEndPoint: destination.ServiceEndpoint,
		RecipientKeys:   destination.RecipientKeys,
		RoutingKeys:     destination.RoutingKeys,
		Namespace:       connection.MyNSPrefix,
		DIDCommVersion:  service.V2,
	}

	for _, opt := range opts {
		opt(&connRec)
	}

	err = c.connectionRecorder.SaveConnectionRecord(&connRec)
	if err != nil {
		return "", err
	}

	return connID, nil
}

// SetConnectionToDIDCommV2 sets that a connection is using didcomm v2, and associated versions of protocols.
func (c *Client) SetConnectionToDIDCommV2(connID string) error {
	connRec, err := c.connectionRecorder.GetConnectionRecord(connID)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}

	connRec.DIDCommVersion = service.V2

	err = c.connectionRecorder.SaveConnectionRecord(connRec)
	if err != nil {
		return fmt.Errorf("failed to save updated connection: %w", err)
	}

	return nil
}

// CreateConnectionOption options for Client.CreateConnectionV2.
type CreateConnectionOption func(record *connection.Record)

// WithTheirLabel option.
func WithTheirLabel(l string) CreateConnectionOption {
	return func(record *connection.Record) {
		record.TheirLabel = l
	}
}