/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdpresproof "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
)

func getPresentProofController(t *testing.T) *PresentProof {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetPresentProofController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	p, ok := controller.(*PresentProof)
	require.Equal(t, ok, true)

	return p
}

func TestPresentProof_Actions(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := `{"actions":[{"PIID":"ID1"},{"PIID":"ID2"},{"PIID":"ID3"}]}`
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.ActionsCommandMethod] = fakeHandler.exec

		payload := ``

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.Actions(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestPresentProof_SendRequestPresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := mockPIID
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.SendRequestPresentationCommandMethod] = fakeHandler.exec

		payload := `{"my_did":"id","their_did":"id","request_presentation":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.SendRequestPresentation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestPresentProof_SendProposePresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := mockPIID
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.SendProposePresentationCommandMethod] = fakeHandler.exec

		payload := `{"my_did":"id","their_did":"id","propose_presentation":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.SendProposePresentation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestPresentProof_AcceptRequestPresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.AcceptRequestPresentationCommandMethod] = fakeHandler.exec

		payload := `{"piid":"id","presentation":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.AcceptRequestPresentation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestPresentProof_NegotiateRequestPresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.NegotiateRequestPresentationCommandMethod] = fakeHandler.exec

		payload := `{"piid":"id","propose_presentation":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.NegotiateRequestPresentation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestPresentProof_DeclineRequestPresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.DeclineRequestPresentationCommandMethod] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.DeclineRequestPresentation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestPresentProof_AcceptProposePresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.AcceptProposePresentationCommandMethod] = fakeHandler.exec

		payload := `{"piid":"id","request_presentation":{}}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.AcceptProposePresentation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestPresentProof_DeclineProposePresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.DeclineProposePresentationCommandMethod] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.DeclineProposePresentation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestPresentProof_AcceptPresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.AcceptPresentationCommandMethod] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.AcceptPresentation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestPresentProof_AcceptProblemReport(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.AcceptProblemReportCommandMethod] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.AcceptProblemReport(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestPresentProof_DeclinePresentation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := getPresentProofController(t)

		mockResponse := emptyJSON
		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		p.handlers[cmdpresproof.DeclinePresentationCommandMethod] = fakeHandler.exec

		payload := mockPIID

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := p.DeclinePresentation(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}
