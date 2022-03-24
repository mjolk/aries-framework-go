/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	outofbandv2svc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid outofband controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.OutofbandV2)
	// CreateInvitationErrorCode is for failures in create invitation command.
	CreateInvitationErrorCode
	// AcceptInvitationErrorCode is for failures in accept invitation command.
	AcceptInvitationErrorCode
)

// constants for out-of-band v2.
const (
	// command name.
	CommandName                   = "outofbandv2"
	CreateInvitationCommandMethod = "CreateInvitation"
	AcceptInvitationCommandMethod = "AcceptInvitation"

	// error messages.
	errEmptyRequest = "request was not provided"
	errEmptyMyLabel = "my_label was not provided"

	// log constants.
	successString = "success"
)

var logger = log.New("aries-framework/controller/outofbandv2")

// Command is controller command for outofband.
type Command struct {
	client *outofbandv2.Client
}

// New returns new outofband controller command instance.
func New(ctx outofbandv2.Provider) (*Command, error) {
	client, err := outofbandv2.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot create a client: %w", err)
	}

	return &Command{client: client}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, CreateInvitationCommandMethod, c.CreateInvitation),
		cmdutil.NewCommandHandler(CommandName, AcceptInvitationCommandMethod, c.AcceptInvitation),
	}
}

// CreateInvitation creates an out-of-bandv2 invitation.
// Protocols is an optional list of protocol identifier URIs that can be used to form connections. A default
// will be set if none are provided.
func (c *Command) CreateInvitation(rw io.Writer, req io.Reader) command.Error {
	var args CreateInvitationArgs
	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, CreateInvitationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	invitation, err := c.client.CreateInvitation(
		outofbandv2.WithGoal(args.Body.Goal, args.Body.GoalCode),
		outofbandv2.WithLabel(args.Label),
		outofbandv2.WithFrom(args.From),
		outofbandv2.WithAccept(args.Body.Accept...),
		outofbandv2.WithAttachments(args.Attachments...),
	)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateInvitationCommandMethod, err.Error())
		return command.NewExecuteError(CreateInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &CreateInvitationResponse{
		Invitation: invitation,
	}, logger)

	logutil.LogDebug(logger, CommandName, CreateInvitationCommandMethod, successString)

	return nil
}

// AcceptInvitation from another agent and return the ID of the new connection records.
func (c *Command) AcceptInvitation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptInvitationArgs
	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptInvitationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.Invitation == nil {
		logutil.LogDebug(logger, CommandName, AcceptInvitationCommandMethod, errEmptyRequest)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequest))
	}

	if args.MyLabel == "" {
		logutil.LogDebug(logger, CommandName, AcceptInvitationCommandMethod, errEmptyMyLabel)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyLabel))
	}

	connID, err := c.client.AcceptInvitation(
		args.Invitation,
		outofbandv2svc.WithRouterConnections(args.RouterConnections),
	)
	if err != nil {
		logutil.LogError(logger, CommandName, AcceptInvitationCommandMethod, err.Error())
		return command.NewExecuteError(AcceptInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptInvitationResponse{ConnectionID: connID}, logger)

	logutil.LogDebug(logger, CommandName, AcceptInvitationCommandMethod, successString)

	return nil
}
