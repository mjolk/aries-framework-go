/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	cmdpresproof "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
)

// PresentProof contains necessary fields for each of its operations.
type PresentProof struct {
	handlers map[string]command.Exec
}

// Actions returns pending actions that have not yet to be executed or canceled.
func (p *PresentProof) Actions(request *models.RequestEnvelope) *models.ResponseEnvelope {
	response, cmdErr := exec(p.handlers[cmdpresproof.ActionsCommandMethod], request.Payload)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SendRequestPresentation is used by the Verifier to send a request presentation.
func (p *PresentProof) SendRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdpresproof.SendRequestPresentationV2Args{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(p.handlers[cmdpresproof.SendRequestPresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// SendProposePresentation is used by the Prover to send a propose presentation.
func (p *PresentProof) SendProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdpresproof.SendProposePresentationV2Args{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(p.handlers[cmdpresproof.SendProposePresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptRequestPresentation is used by the Prover is to accept a presentation request.
func (p *PresentProof) AcceptRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdpresproof.AcceptRequestPresentationV2Args{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(p.handlers[cmdpresproof.AcceptRequestPresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// NegotiateRequestPresentation is used by the Prover to counter a presentation request they received with a proposal.
func (p *PresentProof) NegotiateRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdpresproof.NegotiateRequestPresentationV2Args{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(p.handlers[cmdpresproof.NegotiateRequestPresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// DeclineRequestPresentation is used when the Prover does not want to accept the request presentation.
func (p *PresentProof) DeclineRequestPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdpresproof.DeclineRequestPresentationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(p.handlers[cmdpresproof.DeclineRequestPresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptProposePresentation is used when the Verifier is willing to accept the propose presentation.
func (p *PresentProof) AcceptProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdpresproof.AcceptProposePresentationV2Args{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(p.handlers[cmdpresproof.AcceptProposePresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// DeclineProposePresentation is used when the Verifier does not want to accept the propose presentation.
func (p *PresentProof) DeclineProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdpresproof.DeclineProposePresentationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(p.handlers[cmdpresproof.DeclineProposePresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptPresentation is used by the Verifier to accept a presentation.
func (p *PresentProof) AcceptPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdpresproof.AcceptPresentationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(p.handlers[cmdpresproof.AcceptPresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// AcceptProblemReport is used for accepting problem report.
func (p *PresentProof) AcceptProblemReport(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdpresproof.AcceptProblemReportArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(p.handlers[cmdpresproof.AcceptProblemReportCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// DeclinePresentation is used by the Verifier to decline a presentation.
func (p *PresentProof) DeclinePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdpresproof.DeclinePresentationArgs{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(p.handlers[cmdpresproof.DeclinePresentationCommandMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
