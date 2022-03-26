/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"net/http"

	cmddidexch "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	cmdintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	cmdisscred "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	cmdkms "github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
	cmdld "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	cmdmediator "github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
	cmdmessaging "github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	cmdoob "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	cmdpresproof "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	cmdvcwallet "github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	cmdvdr "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
	cmdverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	opdidexch "github.com/hyperledger/aries-framework-go/pkg/controller/rest/didexchange"
	opintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/rest/introduce"
	opisscred "github.com/hyperledger/aries-framework-go/pkg/controller/rest/issuecredential"
	opkms "github.com/hyperledger/aries-framework-go/pkg/controller/rest/kms"
	opld "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	opmediator "github.com/hyperledger/aries-framework-go/pkg/controller/rest/mediator"
	opmessaging "github.com/hyperledger/aries-framework-go/pkg/controller/rest/messaging"
	opoob "github.com/hyperledger/aries-framework-go/pkg/controller/rest/outofband"
	oppresproof "github.com/hyperledger/aries-framework-go/pkg/controller/rest/presentproof"
	opvcwallet "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vcwallet"
	opvdr "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdr"
	opverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/rest/verifiable"
)

// endpoint describes the fields for making calls to external agents.
type endpoint struct {
	Path   string
	Method string
}

func getControllerEndpoints() map[string]map[string]*endpoint {
	allEndpoints := make(map[string]map[string]*endpoint)

	allEndpoints[opintroduce.OperationID] = getIntroduceEndpoints()
	allEndpoints[opverifiable.OperationID] = getVerifiableEndpoints()
	allEndpoints[opdidexch.OperationID] = getDIDExchangeEndpoints()
	allEndpoints[opisscred.OperationID] = getIssueCredentialEndpoints()
	allEndpoints[oppresproof.OperationID] = getPresentProofEndpoints()
	allEndpoints[opvdr.OperationID] = getVDREndpoints()
	allEndpoints[opmediator.OperationID] = getMediatorEndpoints()
	allEndpoints[opmessaging.OperationID] = getMessagingEndpoints()
	allEndpoints[opoob.OperationID] = getOutOfBandEndpoints()
	allEndpoints[opkms.OperationID] = getKMSEndpoints()
	allEndpoints[opld.OperationID] = getLDEndpoints()
	allEndpoints[opvcwallet.OperationID] = getVCWalletEndpoints()

	return allEndpoints
}

func getIntroduceEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdintroduce.ActionsCommandMethod: {
			Path:   opintroduce.Actions,
			Method: http.MethodGet,
		},
		cmdintroduce.SendProposalCommandMethod: {
			Path:   opintroduce.SendProposal,
			Method: http.MethodPost,
		},
		cmdintroduce.SendProposalWithOOBInvitationCommandMethod: {
			Path:   opintroduce.SendProposalWithOOBInvitation,
			Method: http.MethodPost,
		},
		cmdintroduce.SendRequestCommandMethod: {
			Path:   opintroduce.SendRequest,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptProposalWithOOBInvitationCommandMethod: {
			Path:   opintroduce.AcceptProposalWithOOBInvitation,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptProposalCommandMethod: {
			Path:   opintroduce.AcceptProposal,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptRequestWithPublicOOBInvitationCommandMethod: {
			Path:   opintroduce.AcceptRequestWithPublicOOBInvitation,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptRequestWithRecipientsCommandMethod: {
			Path:   opintroduce.AcceptRequestWithRecipients,
			Method: http.MethodPost,
		},
		cmdintroduce.DeclineProposalCommandMethod: {
			Path:   opintroduce.DeclineProposal,
			Method: http.MethodPost,
		},
		cmdintroduce.DeclineRequestCommandMethod: {
			Path:   opintroduce.DeclineRequest,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptProblemReportCommandMethod: {
			Path:   opintroduce.AcceptProblemReport,
			Method: http.MethodPost,
		},
	}
}

func getVerifiableEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdverifiable.ValidateCredentialCommandMethod: {
			Path:   opverifiable.ValidateCredential,
			Method: http.MethodPost,
		},
		cmdverifiable.SaveCredentialCommandMethod: {
			Path:   opverifiable.SaveCredential,
			Method: http.MethodPost,
		},
		cmdverifiable.SavePresentationCommandMethod: {
			Path:   opverifiable.SavePresentation,
			Method: http.MethodPost,
		},
		cmdverifiable.GetCredentialCommandMethod: {
			Path:   opverifiable.GetCredential,
			Method: http.MethodGet,
		},
		cmdverifiable.SignCredentialCommandMethod: {
			Path:   opverifiable.SignCredentials,
			Method: http.MethodPost,
		},
		cmdverifiable.GetPresentationCommandMethod: {
			Path:   opverifiable.GetPresentation,
			Method: http.MethodGet,
		},
		cmdverifiable.GetCredentialByNameCommandMethod: {
			Path:   opverifiable.GetCredentialByName,
			Method: http.MethodGet,
		},
		cmdverifiable.GetCredentialsCommandMethod: {
			Path:   opverifiable.GetCredentials,
			Method: http.MethodGet,
		},
		cmdverifiable.GetPresentationsCommandMethod: {
			Path:   opverifiable.GetPresentations,
			Method: http.MethodGet,
		},
		cmdverifiable.GeneratePresentationCommandMethod: {
			Path:   opverifiable.GeneratePresentation,
			Method: http.MethodPost,
		},
		cmdverifiable.GeneratePresentationByIDCommandMethod: {
			Path:   opverifiable.GeneratePresentationByID,
			Method: http.MethodPost,
		},
		cmdverifiable.RemoveCredentialByNameCommandMethod: {
			Path:   opverifiable.RemoveCredentialByName,
			Method: http.MethodPost,
		},
		cmdverifiable.RemovePresentationByNameCommandMethod: {
			Path:   opverifiable.RemovePresentationByName,
			Method: http.MethodPost,
		},
	}
}

func getDIDExchangeEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmddidexch.CreateInvitationCommandMethod: {
			Path:   opdidexch.CreateInvitation,
			Method: http.MethodPost,
		},
		cmddidexch.ReceiveInvitationCommandMethod: {
			Path:   opdidexch.ReceiveInvitation,
			Method: http.MethodPost,
		},
		cmddidexch.AcceptInvitationCommandMethod: {
			Path:   opdidexch.AcceptInvitation,
			Method: http.MethodPost,
		},
		cmddidexch.CreateImplicitInvitationCommandMethod: {
			Path:   opdidexch.CreateImplicitInvitation,
			Method: http.MethodPost,
		},
		cmddidexch.AcceptExchangeRequestCommandMethod: {
			Path:   opdidexch.AcceptExchangeRequest,
			Method: http.MethodPost,
		},
		cmddidexch.QueryConnectionsCommandMethod: {
			Path:   opdidexch.QueryConnections,
			Method: http.MethodGet,
		},
		cmddidexch.QueryConnectionByIDCommandMethod: {
			Path:   opdidexch.QueryConnectionsByID,
			Method: http.MethodGet,
		},
		cmddidexch.CreateConnectionCommandMethod: {
			Path:   opdidexch.CreateConnection,
			Method: http.MethodPost,
		},
		cmddidexch.RemoveConnectionCommandMethod: {
			Path:   opdidexch.RemoveConnection,
			Method: http.MethodPost,
		},
	}
}

func getIssueCredentialEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdisscred.ActionsCommandMethod: {
			Path:   opisscred.Actions,
			Method: http.MethodGet,
		},
		cmdisscred.SendOfferCommandMethod: {
			Path:   opisscred.SendOffer,
			Method: http.MethodPost,
		},
		cmdisscred.SendProposalCommandMethod: {
			Path:   opisscred.SendProposal,
			Method: http.MethodPost,
		},
		cmdisscred.SendRequestCommandMethod: {
			Path:   opisscred.SendRequest,
			Method: http.MethodPost,
		},
		cmdisscred.AcceptProposalCommandMethod: {
			Path:   opisscred.AcceptProposal,
			Method: http.MethodPost,
		},
		cmdisscred.NegotiateProposalCommandMethod: {
			Path:   opisscred.NegotiateProposal,
			Method: http.MethodPost,
		},
		cmdisscred.DeclineProposalCommandMethod: {
			Path:   opisscred.DeclineProposal,
			Method: http.MethodPost,
		},
		cmdisscred.AcceptOfferCommandMethod: {
			Path:   opisscred.AcceptOffer,
			Method: http.MethodPost,
		},
		cmdisscred.AcceptProblemReportCommandMethod: {
			Path:   opisscred.AcceptProblemReport,
			Method: http.MethodPost,
		},
		cmdisscred.DeclineOfferCommandMethod: {
			Path:   opisscred.DeclineOffer,
			Method: http.MethodPost,
		},
		cmdisscred.AcceptRequestCommandMethod: {
			Path:   opisscred.AcceptRequest,
			Method: http.MethodPost,
		},
		cmdisscred.DeclineRequestCommandMethod: {
			Path:   opisscred.DeclineRequest,
			Method: http.MethodPost,
		},
		cmdisscred.AcceptCredentialCommandMethod: {
			Path:   opisscred.AcceptCredential,
			Method: http.MethodPost,
		},
		cmdisscred.DeclineCredentialCommandMethod: {
			Path:   opisscred.DeclineCredential,
			Method: http.MethodPost,
		},
	}
}

func getPresentProofEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdpresproof.ActionsCommandMethod: {
			Path:   oppresproof.Actions,
			Method: http.MethodGet,
		},
		cmdpresproof.SendRequestPresentationCommandMethod: {
			Path:   oppresproof.SendRequestPresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.SendProposePresentationCommandMethod: {
			Path:   oppresproof.SendProposePresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.AcceptRequestPresentationCommandMethod: {
			Path:   oppresproof.AcceptRequestPresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.NegotiateRequestPresentationCommandMethod: {
			Path:   oppresproof.NegotiateRequestPresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.DeclineRequestPresentationCommandMethod: {
			Path:   oppresproof.DeclineRequestPresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.AcceptProposePresentationCommandMethod: {
			Path:   oppresproof.AcceptProposePresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.DeclineProposePresentationCommandMethod: {
			Path:   oppresproof.DeclineProposePresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.AcceptPresentationCommandMethod: {
			Path:   oppresproof.AcceptPresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.AcceptProblemReportCommandMethod: {
			Path:   oppresproof.AcceptProblemReport,
			Method: http.MethodPost,
		},
		cmdpresproof.DeclinePresentationCommandMethod: {
			Path:   oppresproof.DeclinePresentation,
			Method: http.MethodPost,
		},
	}
}

func getVDREndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdvdr.GetDIDCommandMethod: {
			Path:   opvdr.GetDID,
			Method: http.MethodGet,
		},
		cmdvdr.GetDIDsCommandMethod: {
			Path:   opvdr.GetDIDRecords,
			Method: http.MethodGet,
		},
		cmdvdr.SaveDIDCommandMethod: {
			Path:   opvdr.SaveDID,
			Method: http.MethodPost,
		},
		cmdvdr.ResolveDIDCommandMethod: {
			Path:   opvdr.ResolveDID,
			Method: http.MethodGet,
		},
		cmdvdr.CreateDIDCommandMethod: {
			Path:   opvdr.CreateDID,
			Method: http.MethodPost,
		},
	}
}

func getMediatorEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdmediator.RegisterCommandMethod: {
			Path:   opmediator.Register,
			Method: http.MethodPost,
		},
		cmdmediator.UnregisterCommandMethod: {
			Path:   opmediator.Unregister,
			Method: http.MethodDelete,
		},
		cmdmediator.GetConnectionsCommandMethod: {
			Path:   opmediator.GetConnections,
			Method: http.MethodGet,
		},
		cmdmediator.ReconnectCommandMethod: {
			Path:   opmediator.Reconnect,
			Method: http.MethodPost,
		},
		cmdmediator.ReconnectAllCommandMethod: {
			Path:   opmediator.ReconnectAll,
			Method: http.MethodGet,
		},
		cmdmediator.StatusCommandMethod: {
			Path:   opmediator.Status,
			Method: http.MethodPost,
		},
		cmdmediator.BatchPickupCommandMethod: {
			Path:   opmediator.BatchPickup,
			Method: http.MethodPost,
		},
	}
}

func getMessagingEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdmessaging.RegisterMessageServiceCommandMethod: {
			Path:   opmessaging.RegisterMessageService,
			Method: http.MethodPost,
		},
		cmdmessaging.UnregisterMessageServiceCommandMethod: {
			Path:   opmessaging.UnregisterMessageService,
			Method: http.MethodPost,
		},
		cmdmessaging.RegisteredServicesCommandMethod: {
			Path:   opmessaging.RegisteredServices,
			Method: http.MethodGet,
		},
		cmdmessaging.SendNewMessageCommandMethod: {
			Path:   opmessaging.SendNewMessage,
			Method: http.MethodPost,
		},
		cmdmessaging.SendReplyMessageCommandMethod: {
			Path:   opmessaging.SendReplyMessage,
			Method: http.MethodPost,
		},
		cmdmessaging.RegisterHTTPMessageServiceCommandMethod: {
			Path:   opmessaging.RegisterHTTPMessageService,
			Method: http.MethodPost,
		},
	}
}

func getOutOfBandEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdoob.ActionsCommandMethod: {
			Path:   opoob.Actions,
			Method: http.MethodGet,
		},
		cmdoob.AcceptInvitationCommandMethod: {
			Path:   opoob.AcceptInvitation,
			Method: http.MethodPost,
		},
		cmdoob.CreateInvitationCommandMethod: {
			Path:   opoob.CreateInvitation,
			Method: http.MethodPost,
		},
		cmdoob.ActionContinueCommandMethod: {
			Path:   opoob.ActionContinue,
			Method: http.MethodPost,
		},
		cmdoob.ActionStopCommandMethod: {
			Path:   opoob.ActionStop,
			Method: http.MethodPost,
		},
	}
}

func getKMSEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdkms.CreateKeySetCommandMethod: {
			Path:   opkms.CreateKeySet,
			Method: http.MethodPost,
		},
		cmdkms.ImportKeyCommandMethod: {
			Path:   opkms.ImportKey,
			Method: http.MethodPost,
		},
	}
}

func getLDEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdld.AddContextsCommandMethod: {
			Path:   opld.AddContexts,
			Method: http.MethodPost,
		},
		cmdld.AddRemoteProviderCommandMethod: {
			Path:   opld.AddRemoteProvider,
			Method: http.MethodPost,
		},
		cmdld.RefreshRemoteProviderCommandMethod: {
			Path:   opld.RefreshRemoteProvider,
			Method: http.MethodPost,
		},
		cmdld.DeleteRemoteProviderCommandMethod: {
			Path:   opld.DeleteRemoteProvider,
			Method: http.MethodDelete,
		},
		cmdld.GetAllRemoteProvidersCommandMethod: {
			Path:   opld.GetAllRemoteProviders,
			Method: http.MethodGet,
		},
		cmdld.RefreshAllRemoteProvidersCommandMethod: {
			Path:   opld.RefreshAllRemoteProviders,
			Method: http.MethodPost,
		},
	}
}

func getVCWalletEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdvcwallet.CreateProfileMethodCommandMethod: {
			Path: opvcwallet.CreateProfilePath, Method: http.MethodPost,
		},
		cmdvcwallet.UpdateProfileMethodCommandMethod: {
			Path: opvcwallet.UpdateProfilePath, Method: http.MethodPost,
		},
		cmdvcwallet.ProfileExistsMethodCommandMethod: {
			Path: opvcwallet.ProfileExistsPath, Method: http.MethodGet,
		},
		cmdvcwallet.OpenCommandMethod: {
			Path: opvcwallet.Open, Method: http.MethodPost,
		},
		cmdvcwallet.CloseCommandMethod: {
			Path: opvcwallet.Close, Method: http.MethodPost,
		},
		cmdvcwallet.AddCommandMethod: {
			Path: opvcwallet.Add, Method: http.MethodPost,
		},
		cmdvcwallet.RemoveCommandMethod: {
			Path: opvcwallet.Remove, Method: http.MethodPost,
		},
		cmdvcwallet.GetCommandMethod: {
			Path: opvcwallet.Get, Method: http.MethodPost,
		},
		cmdvcwallet.GetAllCommandMethod: {
			Path: opvcwallet.GetAll, Method: http.MethodPost,
		},
		cmdvcwallet.QueryCommandMethod: {
			Path: opvcwallet.Query, Method: http.MethodPost,
		},
		cmdvcwallet.IssueCommandMethod: {
			Path: opvcwallet.Issue, Method: http.MethodPost,
		},
		cmdvcwallet.ProveCommandMethod: {
			Path: opvcwallet.Prove, Method: http.MethodPost,
		},
		cmdvcwallet.VerifyCommandMethod: {
			Path: opvcwallet.Verify, Method: http.MethodPost,
		},
		cmdvcwallet.DeriveCommandMethod: {
			Path: opvcwallet.Derive, Method: http.MethodPost,
		},
		cmdvcwallet.CreateKeyPairCommandMethod: {
			Path: opvcwallet.CreateKeyPair, Method: http.MethodPost,
		},
		cmdvcwallet.ConnectCommandMethod: {
			Path: opvcwallet.Connect, Method: http.MethodPost,
		},
		cmdvcwallet.ProposePresentationCommandMethod: {
			Path: opvcwallet.ProposePresentation, Method: http.MethodPost,
		},
		cmdvcwallet.PresentProofCommandMethod: {
			Path: opvcwallet.PresentProof, Method: http.MethodPost,
		},
	}
}
