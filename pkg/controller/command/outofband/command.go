/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid outofband controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.Outofband)
	// CreateInvitationErrorCode is for failures in create invitation command.
	CreateInvitationErrorCode
	// AcceptInvitationErrorCode is for failures in accept invitation command.
	AcceptInvitationErrorCode
	// ActionStopErrorCode is for failures in action stop command.
	ActionStopErrorCode
	// ActionsErrorCode is for failures in actions command.
	ActionsErrorCode
	// ActionContinueErrorCode is for failures in action continue command.
	ActionContinueErrorCode
)

// constants for out-of-band.
const (
	// command name.
	CommandName                   = "outofband"
	CreateInvitationCommandMethod = "CreateInvitation"
	AcceptInvitationCommandMethod = "AcceptInvitation"
	ActionStopCommandMethod       = "ActionStop"
	ActionsCommandMethod          = "Actions"
	ActionContinueCommandMethod   = "ActionContinue"

	// error messages.
	errEmptyRequest = "request was not provided"
	errEmptyMyLabel = "my_label was not provided"
	errEmptyPIID    = "piid was not provided"
	// log constants.
	successString = "success"

	_actions = "_actions"
	_states  = "_states"
)

var logger = log.New("aries-framework/controller/outofband")

// Command is controller command for outofband.
type Command struct {
	client *outofband.Client
}

// New returns new outofband controller command instance.
func New(ctx outofband.Provider, notifier command.Notifier) (*Command, error) {
	client, err := outofband.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot create a client: %w", err)
	}

	// creates action channel
	actions := make(chan service.DIDCommAction)
	// registers action channel to listen for events
	if err := client.RegisterActionEvent(actions); err != nil {
		return nil, fmt.Errorf("register action event: %w", err)
	}

	// creates state channel
	states := make(chan service.StateMsg)
	// registers state channel to listen for events
	if err := client.RegisterMsgEvent(states); err != nil {
		return nil, fmt.Errorf("register msg event: %w", err)
	}

	obs := webnotifier.NewObserver(notifier)
	obs.RegisterAction(protocol.Name+_actions, actions)
	obs.RegisterStateMsg(protocol.Name+_states, states)

	return &Command{client: client}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, CreateInvitationCommandMethod, c.CreateInvitation),
		cmdutil.NewCommandHandler(CommandName, AcceptInvitationCommandMethod, c.AcceptInvitation),
		cmdutil.NewCommandHandler(CommandName, ActionsCommandMethod, c.Actions),
		cmdutil.NewCommandHandler(CommandName, ActionContinueCommandMethod, c.ActionContinue),
		cmdutil.NewCommandHandler(CommandName, ActionStopCommandMethod, c.ActionStop),
	}
}

// CreateInvitation creates and saves an out-of-band invitation.
// Protocols is an optional list of protocol identifier URIs that can be used to form connections. A default
// will be set if none are provided.
func (c *Command) CreateInvitation(rw io.Writer, req io.Reader) command.Error {
	var args CreateInvitationArgs
	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, CreateInvitationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	invitation, err := c.client.CreateInvitation(
		args.Service,
		outofband.WithGoal(args.Goal, args.GoalCode),
		outofband.WithLabel(args.Label),
		outofband.WithHandshakeProtocols(args.Protocols...),
		outofband.WithRouterConnections(args.RouterConnectionID),
		outofband.WithAccept(args.Accept...),
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

	options := []outofband.MessageOption{
		outofband.WithRouterConnections(strings.Split(args.RouterConnections, ",")...),
		outofband.ReuseConnection(args.ReuseConnection),
	}

	if args.ReuseAnyConnection {
		options = append(options, outofband.ReuseAnyConnection())
	}

	connID, err := c.client.AcceptInvitation(args.Invitation, args.MyLabel, options...)
	if err != nil {
		logutil.LogError(logger, CommandName, AcceptInvitationCommandMethod, err.Error())
		return command.NewExecuteError(AcceptInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptInvitationResponse{
		ConnectionID: connID,
	}, logger)

	logutil.LogDebug(logger, CommandName, AcceptInvitationCommandMethod, successString)

	return nil
}

// Actions returns pending actions that have not yet to be executed or canceled.
func (c *Command) Actions(rw io.Writer, _ io.Reader) command.Error {
	result, err := c.client.Actions()
	if err != nil {
		logutil.LogError(logger, CommandName, ActionsCommandMethod, err.Error())
		return command.NewExecuteError(ActionsErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ActionsResponse{
		Actions: result,
	}, logger)

	logutil.LogDebug(logger, CommandName, ActionsCommandMethod, successString)

	return nil
}

// ActionContinue allows continuing with the protocol after an action event was triggered.
func (c *Command) ActionContinue(rw io.Writer, req io.Reader) command.Error {
	var args ActionContinueArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, ActionContinueCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, ActionContinueCommandMethod, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	err := c.client.ActionContinue(args.PIID, args.Label,
		outofband.WithRouterConnections(strings.Split(args.RouterConnections, ",")...))
	if err != nil {
		logutil.LogError(logger, CommandName, ActionContinueCommandMethod, err.Error())
		return command.NewExecuteError(ActionContinueErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ActionContinueResponse{}, logger)

	logutil.LogDebug(logger, CommandName, ActionContinueCommandMethod, successString)

	return nil
}

// ActionStop stops the protocol after an action event was triggered.
func (c *Command) ActionStop(rw io.Writer, req io.Reader) command.Error {
	var args ActionStopArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, ActionStopCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, ActionStopCommandMethod, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.ActionStop(args.PIID, errors.New(args.Reason)); err != nil {
		logutil.LogError(logger, CommandName, ActionStopCommandMethod, err.Error())
		return command.NewExecuteError(ActionStopErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ActionStopResponse{}, logger)

	logutil.LogDebug(logger, CommandName, ActionStopCommandMethod, successString)

	return nil
}
