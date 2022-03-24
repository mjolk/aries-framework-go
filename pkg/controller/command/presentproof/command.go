/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid present proof controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.PresentProof)
	// ActionsErrorCode is for failures in actions command.
	ActionsErrorCode
	// SendRequestPresentationErrorCode is for failures in send request presentation command.
	SendRequestPresentationErrorCode
	// AcceptRequestPresentationErrorCode is for failures in accept request presentation command.
	AcceptRequestPresentationErrorCode
	// AcceptProblemReportErrorCode is for failures in accept problem report command.
	AcceptProblemReportErrorCode
	// NegotiateRequestPresentationErrorCode is for failures in negotiate request presentation command.
	NegotiateRequestPresentationErrorCode
	// DeclineRequestPresentationErrorCode is for failures in decline request presentation command.
	DeclineRequestPresentationErrorCode
	// SendProposePresentationErrorCode is for failures in send propose presentation command.
	SendProposePresentationErrorCode
	// AcceptProposePresentationErrorCode is for failures in accept propose presentation command.
	AcceptProposePresentationErrorCode
	// DeclineProposePresentationErrorCode is for failures in decline propose presentation command.
	DeclineProposePresentationErrorCode
	// AcceptPresentationErrorCode is for failures in accept presentation command.
	AcceptPresentationErrorCode
	// DeclinePresentationErrorCode is for failures in decline presentation command.
	DeclinePresentationErrorCode
)

// constants for the PresentProof operations.
const (
	// command name.
	CommandName = "presentproof"

	ActionsCommandMethod                        = "Actions"
	SendRequestPresentationCommandMethod        = "SendRequestPresentation"
	SendRequestPresentationV2CommandMethod      = "SendRequestPresentationV2"
	SendRequestPresentationV3CommandMethod      = "SendRequestPresentationV3"
	AcceptRequestPresentationCommandMethod      = "AcceptRequestPresentation"
	AcceptRequestPresentationV2CommandMethod    = "AcceptRequestPresentationV2"
	AcceptRequestPresentationV3CommandMethod    = "AcceptRequestPresentationV3"
	NegotiateRequestPresentationCommandMethod   = "NegotiateRequestPresentation"
	NegotiateRequestPresentationV2CommandMethod = "NegotiateRequestPresentationV2"
	NegotiateRequestPresentationV3CommandMethod = "NegotiateRequestPresentationV3"
	AcceptProblemReportCommandMethod            = "AcceptProblemReport"
	DeclineRequestPresentationCommandMethod     = "DeclineRequestPresentation"
	SendProposePresentationCommandMethod        = "SendProposePresentation"
	SendProposePresentationV2CommandMethod      = "SendProposePresentationV2"
	SendProposePresentationV3CommandMethod      = "SendProposePresentationV3"
	AcceptProposePresentationCommandMethod      = "AcceptProposePresentation"
	AcceptProposePresentationV2CommandMethod    = "AcceptProposePresentationV2"
	AcceptProposePresentationV3CommandMethod    = "AcceptProposePresentationV3"
	DeclineProposePresentationCommandMethod     = "DeclineProposePresentation"
	AcceptPresentationCommandMethod             = "AcceptPresentation"
	DeclinePresentationCommandMethod            = "DeclinePresentation"
)

const (
	// error messages.
	errEmptyPIID                = "empty PIID"
	errEmptyMyDID               = "empty MyDID"
	errEmptyTheirDID            = "empty TheirDID"
	errEmptyPresentation        = "empty Presentation"
	errEmptyProposePresentation = "empty ProposePresentation"
	errEmptyRequestPresentation = "empty RequestPresentation"
	errNoConnectionForDIDs      = "no connection for given DIDs"
	errNoConnectionByID         = "no connection for given connection ID"

	// log constants.
	successString = "success"

	_actions = "_actions"
	_states  = "_states"
)

var logger = log.New("aries-framework/controller/presentproof")

// Command is controller command for present proof.
type Command struct {
	client *presentproof.Client
	lookup *connection.Lookup
}

// Provider contains dependencies for the protocol and is typically created by using aries.Context().
type Provider interface {
	Service(id string) (interface{}, error)
	ConnectionLookup() *connection.Lookup
}

// New returns new present proof controller command instance.
func New(ctx Provider, notifier command.Notifier) (*Command, error) {
	client, err := presentproof.New(ctx)
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

	return &Command{
		client: client,
		lookup: ctx.ConnectionLookup(),
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, ActionsCommandMethod, c.Actions),
		cmdutil.NewCommandHandler(CommandName, SendRequestPresentationCommandMethod, c.SendRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, SendRequestPresentationV3CommandMethod, c.SendRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptRequestPresentationCommandMethod, c.AcceptRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptRequestPresentationV3CommandMethod, c.AcceptRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, NegotiateRequestPresentationCommandMethod, c.NegotiateRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, NegotiateRequestPresentationV3CommandMethod, c.NegotiateRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, DeclineRequestPresentationCommandMethod, c.DeclineRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, SendProposePresentationCommandMethod, c.SendProposePresentation),
		cmdutil.NewCommandHandler(CommandName, SendProposePresentationV3CommandMethod, c.SendProposePresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptProposePresentationCommandMethod, c.AcceptProposePresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptProposePresentationV3CommandMethod, c.AcceptProposePresentation),
		cmdutil.NewCommandHandler(CommandName, DeclineProposePresentationCommandMethod, c.DeclineProposePresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptPresentationCommandMethod, c.AcceptPresentation),
		cmdutil.NewCommandHandler(CommandName, DeclinePresentationCommandMethod, c.DeclinePresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptProblemReportCommandMethod, c.AcceptProblemReport),
	}
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

// SendRequestPresentation is used by the Verifier to send a request presentation.
func (c *Command) SendRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var (
		args   SendRequestPresentationArgs
		err    error
		errMsg string
		rec    *connection.Record
	)

	if err = json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, SendRequestPresentationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.ConnectionID == "" {
		if args.MyDID == "" {
			logutil.LogDebug(logger, CommandName, SendRequestPresentationCommandMethod, errEmptyMyDID)
			return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
		}

		if args.TheirDID == "" {
			logutil.LogDebug(logger, CommandName, SendRequestPresentationCommandMethod, errEmptyTheirDID)
			return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
		}
	}

	if args.RequestPresentation == nil {
		logutil.LogDebug(logger, CommandName, SendRequestPresentationCommandMethod, errEmptyRequestPresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequestPresentation))
	}

	if args.ConnectionID == "" {
		rec, err = c.lookup.GetConnectionRecordByDIDs(args.MyDID, args.TheirDID)
		errMsg = errNoConnectionForDIDs
	} else {
		rec, err = c.lookup.GetConnectionRecord(args.ConnectionID)
		errMsg = errNoConnectionByID
	}

	if err != nil {
		logutil.LogDebug(logger, CommandName, SendRequestPresentationCommandMethod, errMsg)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errMsg))
	}

	piid, err := c.client.SendRequestPresentation(args.RequestPresentation, rec)
	if err != nil {
		logutil.LogError(logger, CommandName, SendRequestPresentationCommandMethod, err.Error())
		return command.NewExecuteError(SendRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendRequestPresentationResponse{
		PIID: piid,
	}, logger)

	logutil.LogDebug(logger, CommandName, SendRequestPresentationCommandMethod, successString)

	return nil
}

// SendProposePresentation is used by the Prover to send a propose presentation.
func (c *Command) SendProposePresentation(rw io.Writer, req io.Reader) command.Error {
	var (
		args   SendProposePresentationArgs
		err    error
		errMsg string
		rec    *connection.Record
	)

	if err = json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, SendProposePresentationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.ConnectionID == "" {
		if args.MyDID == "" {
			logutil.LogDebug(logger, CommandName, SendProposePresentationCommandMethod, errEmptyMyDID)
			return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
		}

		if args.TheirDID == "" {
			logutil.LogDebug(logger, CommandName, SendProposePresentationCommandMethod, errEmptyTheirDID)
			return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
		}
	}

	if args.ProposePresentation == nil {
		logutil.LogDebug(logger, CommandName, SendProposePresentationCommandMethod, errEmptyProposePresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyProposePresentation))
	}

	if args.ConnectionID == "" {
		rec, err = c.lookup.GetConnectionRecordByDIDs(args.MyDID, args.TheirDID)
		errMsg = errNoConnectionForDIDs
	} else {
		rec, err = c.lookup.GetConnectionRecord(args.ConnectionID)
		errMsg = errNoConnectionByID
	}

	if err != nil {
		logutil.LogDebug(logger, CommandName, SendProposePresentationCommandMethod, errMsg)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errMsg))
	}

	piid, err := c.client.SendProposePresentation(args.ProposePresentation, rec)
	if err != nil {
		logutil.LogError(logger, CommandName, SendProposePresentationCommandMethod, err.Error())
		return command.NewExecuteError(SendProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendProposePresentationResponse{
		PIID: piid,
	}, logger)

	logutil.LogDebug(logger, CommandName, SendProposePresentationCommandMethod, successString)

	return nil
}

// AcceptRequestPresentation is used by the Prover is to accept a presentation request.
func (c *Command) AcceptRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptRequestPresentationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptRequestPresentationCommandMethod, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.Presentation == nil {
		logutil.LogDebug(logger, CommandName, AcceptRequestPresentationCommandMethod, errEmptyPresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPresentation))
	}

	if err := c.client.AcceptRequestPresentation(args.PIID, args.Presentation, nil); err != nil {
		logutil.LogError(logger, CommandName, AcceptRequestPresentationCommandMethod, err.Error())
		return command.NewExecuteError(AcceptRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptRequestPresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptRequestPresentationCommandMethod, successString)

	return nil
}

// NegotiateRequestPresentation is used by the Prover to counter a presentation request they received with a proposal.
func (c *Command) NegotiateRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args NegotiateRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, NegotiateRequestPresentationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, NegotiateRequestPresentationCommandMethod, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.ProposePresentation == nil {
		logutil.LogDebug(logger, CommandName, NegotiateRequestPresentationCommandMethod, errEmptyProposePresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyProposePresentation))
	}

	if err := c.client.NegotiateRequestPresentation(args.PIID, args.ProposePresentation); err != nil {
		logutil.LogError(logger, CommandName, NegotiateRequestPresentationCommandMethod, err.Error())
		return command.NewExecuteError(NegotiateRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &NegotiateRequestPresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, NegotiateRequestPresentationCommandMethod, successString)

	return nil
}

// DeclineRequestPresentation is used when the Prover does not want to accept the request presentation.
func (c *Command) DeclineRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args DeclineRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, DeclineRequestPresentationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, DeclineRequestPresentationCommandMethod, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineRequestPresentation(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, CommandName, DeclineRequestPresentationCommandMethod, err.Error())
		return command.NewExecuteError(DeclineRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineRequestPresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclineRequestPresentationCommandMethod, successString)

	return nil
}

// AcceptProposePresentation is used when the Verifier is willing to accept the propose presentation.
func (c *Command) AcceptProposePresentation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptProposePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptProposePresentationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptProposePresentationCommandMethod, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.RequestPresentation == nil {
		logutil.LogDebug(logger, CommandName, AcceptProposePresentationCommandMethod, errEmptyRequestPresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequestPresentation))
	}

	if err := c.client.AcceptProposePresentation(args.PIID, args.RequestPresentation); err != nil {
		logutil.LogError(logger, CommandName, AcceptProposePresentationCommandMethod, err.Error())
		return command.NewExecuteError(AcceptProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProposePresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptProposePresentationCommandMethod, successString)

	return nil
}

// DeclineProposePresentation is used when the Verifier does not want to accept the propose presentation.
func (c *Command) DeclineProposePresentation(rw io.Writer, req io.Reader) command.Error {
	var args DeclineProposePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, DeclineProposePresentationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, DeclineProposePresentationCommandMethod, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineProposePresentation(args.PIID,
		presentproof.DeclineReason(args.Reason), presentproof.DeclineRedirect(args.RedirectURL)); err != nil {
		logutil.LogError(logger, CommandName, DeclineProposePresentationCommandMethod, err.Error())
		return command.NewExecuteError(DeclineProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineProposePresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclineProposePresentationCommandMethod, successString)

	return nil
}

// AcceptPresentation is used by the Verifier to accept a presentation.
func (c *Command) AcceptPresentation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptPresentationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptPresentationCommandMethod, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptPresentation(args.PIID, presentproof.AcceptByRequestingRedirect(args.RedirectURL),
		presentproof.AcceptByFriendlyNames(args.Names...)); err != nil {
		logutil.LogError(logger, CommandName, AcceptPresentationCommandMethod, err.Error())
		return command.NewExecuteError(AcceptPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptPresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptPresentationCommandMethod, successString)

	return nil
}

// AcceptProblemReport is used for accepting problem report.
func (c *Command) AcceptProblemReport(rw io.Writer, req io.Reader) command.Error {
	var args AcceptProblemReportArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptProblemReportCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptProblemReportCommandMethod, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptProblemReport(args.PIID); err != nil {
		logutil.LogError(logger, CommandName, AcceptProblemReportCommandMethod, err.Error())
		return command.NewExecuteError(AcceptProblemReportErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProblemReportResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptProblemReportCommandMethod, successString)

	return nil
}

// DeclinePresentation is used by the Verifier to decline a presentation.
func (c *Command) DeclinePresentation(rw io.Writer, req io.Reader) command.Error {
	var args DeclinePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, DeclinePresentationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, DeclinePresentationCommandMethod, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclinePresentation(args.PIID,
		presentproof.DeclineReason(args.Reason), presentproof.DeclineRedirect(args.RedirectURL)); err != nil {
		logutil.LogError(logger, CommandName, DeclinePresentationCommandMethod, err.Error())
		return command.NewExecuteError(DeclinePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclinePresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclinePresentationCommandMethod, successString)

	return nil
}
