package main

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/asc-go/asc"
	"github.com/sagernet/sing-box/cmd/internal/build_shared"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

func main() {
	ctx := context.Background()
	switch os.Args[1] {
	case "next_project_version":
		if len(os.Args) < 3 {
			log.Fatal("platform required: ios, macos, or tvos")
		}
		err := fetchNextProjectVersion(ctx, os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
	case "publish_testflight":
		err := publishTestflight(ctx)
		if err != nil {
			log.Fatal(err)
		}
	case "cancel_app_store":
		err := cancelAppStore(ctx, os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
	case "prepare_app_store":
		err := prepareAppStore(ctx)
		if err != nil {
			log.Fatal(err)
		}
	case "publish_app_store":
		err := publishAppStore(ctx)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("unknown action: ", os.Args[1])
	}
}

func requiredEnvironment(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatal(name, " is not set")
	}
	return value
}

func createClient(expireDuration time.Duration) *asc.Client {
	privateKey, err := os.ReadFile(requiredEnvironment("ASC_KEY_PATH"))
	if err != nil {
		log.Fatal(err)
	}
	tokenConfig, err := asc.NewTokenConfig(requiredEnvironment("ASC_KEY_ID"), requiredEnvironment("ASC_KEY_ISSUER_ID"), expireDuration, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	return asc.NewClient(tokenConfig.Client())
}

func fetchNextProjectVersion(ctx context.Context, platformName string) error {
	var platform asc.Platform
	switch platformName {
	case "ios":
		platform = asc.PlatformIOS
	case "macos":
		platform = asc.PlatformMACOS
	case "tvos":
		platform = asc.PlatformTVOS
	default:
		return E.New("unknown platform: ", platformName)
	}

	query := &asc.ListBuildsQuery{
		FilterApp:                       []string{requiredEnvironment("ASC_APP_ID")},
		FilterPreReleaseVersionPlatform: []string{string(platform)},
		Limit:                           200,
	}
	if platform != asc.PlatformMACOS {
		tagVersion, err := build_shared.ReadTagVersion()
		if err != nil {
			return err
		}
		query.FilterPreReleaseVersionVersion = []string{build_shared.TestFlightVersion(tagVersion)}
	}
	client := createClient(time.Minute)
	builds, _, err := client.Builds.ListBuilds(ctx, query)
	if err != nil {
		return err
	}
	nextProjectVersion := 1
	var projectVersion int
	for _, build := range builds.Data {
		projectVersion, err = strconv.Atoi(*build.Attributes.Version)
		if err != nil {
			return E.Cause(err, "parse version code")
		}
		if projectVersion >= nextProjectVersion {
			nextProjectVersion = projectVersion + 1
		}
	}
	_, err = os.Stdout.WriteString(F.ToString(nextProjectVersion, "\n"))
	return nil
}

func publishTestflight(ctx context.Context) error {
	if len(os.Args) < 3 {
		return E.New("platform required: ios, macos, or tvos")
	}
	var platform asc.Platform
	switch os.Args[2] {
	case "ios":
		platform = asc.PlatformIOS
	case "macos":
		platform = asc.PlatformMACOS
	case "tvos":
		platform = asc.PlatformTVOS
	default:
		return E.New("unknown platform: ", os.Args[2])
	}

	tagVersion, err := build_shared.ReadTagVersion()
	if err != nil {
		return err
	}
	tag := tagVersion.VersionString()

	releaseNotes := F.ToString("sing-box ", tagVersion.String())
	if len(os.Args) >= 4 {
		releaseNotes = strings.Join(os.Args[3:], " ")
	}

	client := createClient(20 * time.Minute)
	appID := requiredEnvironment("ASC_APP_ID")
	groupID := requiredEnvironment("ASC_TESTFLIGHT_GROUP_ID")
	publishDeadline := time.Now().Add(time.Hour)
	testflightType := os.Getenv("ASC_TESTFLIGHT_TYPE")
	if testflightType == "" {
		testflightType = "Internal"
	}
	var internalTesting bool
	switch testflightType {
	case "Internal":
		internalTesting = true
	case "External":
	default:
		return E.New("unknown TestFlight type: ", testflightType)
	}

	log.Info(tag, " validate ", strings.ToLower(testflightType), " group")
	groupResponse, _, err := client.TestFlight.GetBetaGroup(ctx, groupID, nil)
	if err != nil {
		return err
	}
	if groupResponse.Data.Attributes == nil || groupResponse.Data.Attributes.IsInternalGroup == nil {
		return E.New("beta group ", groupID, " does not report its testing type")
	}
	if *groupResponse.Data.Attributes.IsInternalGroup != internalTesting {
		return E.New("beta group ", groupID, " does not match TestFlight type ", testflightType)
	}
	groupAppResponse, _, err := client.TestFlight.GetAppForBetaGroup(ctx, groupID, nil)
	if err != nil {
		return err
	}
	if groupAppResponse.Data.ID != appID {
		return E.New("beta group ", groupID, " does not belong to app ", appID)
	}

	var candidateBuildID string
	log.Info(string(platform), " list builds")
	for {
		builds, _, err := client.Builds.ListBuilds(ctx, &asc.ListBuildsQuery{
			FilterApp:                       []string{appID},
			FilterPreReleaseVersionVersion:  []string{tag},
			FilterPreReleaseVersionPlatform: []string{string(platform)},
			Sort:                            []string{"-uploadedDate"},
			Limit:                           1,
		})
		if err != nil {
			return err
		}
		if len(builds.Data) == 0 {
			if err = waitForTestFlight(publishDeadline, F.ToString(string(platform), " ", tag, " waiting for uploaded build")); err != nil {
				return err
			}
			continue
		}
		build := builds.Data[0]
		if build.Attributes == nil || build.Attributes.Version == nil || build.Attributes.UploadedDate == nil || build.Attributes.ProcessingState == nil {
			return E.New(string(platform), " ", tag, " build ", build.ID, " has incomplete attributes")
		}
		log.Info(string(platform), " ", tag, " found build: ", build.ID, " (", *build.Attributes.Version, ")")
		if candidateBuildID == "" {
			if time.Since(build.Attributes.UploadedDate.Time) > 30*time.Minute {
				if err = waitForTestFlight(publishDeadline, F.ToString(string(platform), " ", tag, " waiting for a newly uploaded build")); err != nil {
					return err
				}
				continue
			}
			candidateBuildID = build.ID
			log.Info(string(platform), " ", tag, " selected build: ", build.ID)
		} else if build.ID != candidateBuildID {
			candidateBuildID = build.ID
			log.Info(string(platform), " ", tag, " selected newer build: ", build.ID)
		}
		if *build.Attributes.ProcessingState != "VALID" {
			if *build.Attributes.ProcessingState == "FAILED" || *build.Attributes.ProcessingState == "INVALID" {
				return E.New(string(platform), " ", tag, " build processing failed: ", *build.Attributes.ProcessingState)
			}
			if err = waitForTestFlight(publishDeadline, F.ToString(string(platform), " ", tag, " waiting for build processing: ", *build.Attributes.ProcessingState)); err != nil {
				return err
			}
			continue
		}
		if internalTesting {
			betaDetail, response, err := client.TestFlight.GetBuildBetaDetailForBuild(ctx, build.ID, nil)
			if response != nil && response.StatusCode == http.StatusNotFound {
				if err = waitForTestFlight(publishDeadline, F.ToString(string(platform), " ", tag, " waiting for internal TestFlight details")); err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
			if betaDetail.Data.Attributes == nil || betaDetail.Data.Attributes.InternalBuildState == nil {
				return E.New(string(platform), " ", tag, " build ", build.ID, " has no internal TestFlight state")
			}
			internalState := *betaDetail.Data.Attributes.InternalBuildState
			switch internalState {
			case asc.InternalBetaStateReadyForBetaTesting, asc.InternalBetaStateInTesting:
			case asc.InternalBetaStateProcessing, asc.InternalBetaStateInExportComplianceReview:
				if err = waitForTestFlight(publishDeadline, F.ToString(string(platform), " ", tag, " waiting for internal TestFlight state: ", internalState)); err != nil {
					return err
				}
				continue
			default:
				return E.New(string(platform), " ", tag, " build is not eligible for internal testing: ", internalState)
			}
		}
		log.Info(string(platform), " ", tag, " list localizations")
		localizations, _, err := client.TestFlight.ListBetaBuildLocalizationsForBuild(ctx, build.ID, nil)
		if err != nil {
			return err
		}
		localization := common.Find(localizations.Data, func(it asc.BetaBuildLocalization) bool {
			return it.Attributes != nil && it.Attributes.Locale != nil && *it.Attributes.Locale == "en-US"
		})
		if localization.ID == "" {
			if internalTesting {
				log.Warn(string(platform), " ", tag, " no en-US localization found")
			} else {
				return E.New(string(platform), " ", tag, " no en-US localization found")
			}
		} else if localization.Attributes == nil || localization.Attributes.WhatsNew == nil || *localization.Attributes.WhatsNew == "" {
			log.Info(string(platform), " ", tag, " update localization")
			_, _, err = client.TestFlight.UpdateBetaBuildLocalization(ctx, localization.ID, common.Ptr(releaseNotes))
			if err != nil {
				return err
			}
		}
		log.Info(string(platform), " ", tag, " check group membership")
		groupBuilds, _, err := client.Builds.ListBuilds(ctx, &asc.ListBuildsQuery{
			FilterID:         []string{build.ID},
			FilterBetaGroups: []string{groupID},
			Limit:            1,
		})
		if err != nil {
			return err
		}
		alreadyPublished := len(groupBuilds.Data) != 0
		if !alreadyPublished {
			log.Info(string(platform), " ", tag, " publish")
			response, err := client.TestFlight.AddBuildsToBetaGroup(ctx, groupID, []string{build.ID})
			if response != nil && (response.StatusCode == http.StatusUnprocessableEntity || response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusConflict) {
				if err = waitForTestFlight(publishDeadline, F.ToString(string(platform), " ", tag, " waiting to add build to beta group")); err != nil {
					return err
				}
				continue
			} else if err != nil {
				return err
			}
		} else {
			log.Info(string(platform), " ", tag, " build is already in beta group")
		}
		if internalTesting {
			for {
				betaDetail, response, err := client.TestFlight.GetBuildBetaDetailForBuild(ctx, build.ID, nil)
				if response != nil && response.StatusCode == http.StatusNotFound {
					if err = waitForTestFlight(publishDeadline, F.ToString(string(platform), " ", tag, " waiting for internal TestFlight details")); err != nil {
						return err
					}
					continue
				}
				if err != nil {
					return err
				}
				if betaDetail.Data.Attributes == nil || betaDetail.Data.Attributes.InternalBuildState == nil {
					return E.New(string(platform), " ", tag, " build ", build.ID, " has no internal TestFlight state")
				}
				internalState := *betaDetail.Data.Attributes.InternalBuildState
				if internalState == asc.InternalBetaStateInTesting {
					return nil
				}
				if internalState != asc.InternalBetaStateReadyForBetaTesting && internalState != asc.InternalBetaStateProcessing && internalState != asc.InternalBetaStateInExportComplianceReview {
					return E.New(string(platform), " ", tag, " build failed to enter internal testing: ", internalState)
				}
				if err = waitForTestFlight(publishDeadline, F.ToString(string(platform), " ", tag, " waiting for internal testing: ", internalState)); err != nil {
					return err
				}
			}
		}
		log.Info(string(platform), " ", tag, " list submissions")
		betaSubmissions, _, err := client.TestFlight.ListBetaAppReviewSubmissions(ctx, &asc.ListBetaAppReviewSubmissionsQuery{
			FilterBuild: []string{build.ID},
		})
		if err != nil {
			return err
		}
		if len(betaSubmissions.Data) == 0 {
			log.Info(string(platform), " ", tag, " create submission")
			_, _, err = client.TestFlight.CreateBetaAppReviewSubmission(ctx, build.ID)
			if err != nil {
				if strings.Contains(err.Error(), "ANOTHER_BUILD_IN_REVIEW") {
					log.Error(err)
					break
				}
				return err
			}
		}
		break
	}
	return nil
}

func waitForTestFlight(deadline time.Time, message string) error {
	if time.Now().After(deadline) {
		return E.New("timed out waiting for TestFlight: ", message)
	}
	log.Info(message)
	time.Sleep(15 * time.Second)
	return nil
}

func cancelAppStore(ctx context.Context, platform string) error {
	switch platform {
	case "ios":
		platform = string(asc.PlatformIOS)
	case "macos":
		platform = string(asc.PlatformMACOS)
	case "tvos":
		platform = string(asc.PlatformTVOS)
	}
	tag, err := build_shared.ReadTag()
	if err != nil {
		return err
	}
	appID := requiredEnvironment("ASC_APP_ID")
	client := createClient(time.Minute)
	for {
		log.Info(platform, " list versions")
		versions, response, err := client.Apps.ListAppStoreVersionsForApp(ctx, appID, &asc.ListAppStoreVersionsQuery{
			FilterPlatform: []string{string(platform)},
		})
		if isRetryable(response) {
			continue
		} else if err != nil {
			return err
		}
		version := common.Find(versions.Data, func(it asc.AppStoreVersion) bool {
			return *it.Attributes.VersionString == tag
		})
		if version.ID == "" {
			return nil
		}
		log.Info(platform, " ", tag, " get submission")
		submission, response, err := client.Submission.GetAppStoreVersionSubmissionForAppStoreVersion(ctx, version.ID, nil)
		if response != nil && response.StatusCode == http.StatusNotFound {
			return nil
		}
		if isRetryable(response) {
			continue
		} else if err != nil {
			return err
		}
		log.Info(platform, " ", tag, " delete submission")
		_, err = client.Submission.DeleteSubmission(ctx, submission.Data.ID)
		if err != nil {
			return err
		}
		return nil
	}
}

func prepareAppStore(ctx context.Context) error {
	tag, err := build_shared.ReadTag()
	if err != nil {
		return err
	}
	appID := requiredEnvironment("ASC_APP_ID")
	client := createClient(time.Minute)
	for _, platform := range []asc.Platform{
		asc.PlatformIOS,
		asc.PlatformMACOS,
		asc.PlatformTVOS,
	} {
		log.Info(string(platform), " list versions")
		versions, _, err := client.Apps.ListAppStoreVersionsForApp(ctx, appID, &asc.ListAppStoreVersionsQuery{
			FilterPlatform: []string{string(platform)},
		})
		if err != nil {
			return err
		}
		version := common.Find(versions.Data, func(it asc.AppStoreVersion) bool {
			return *it.Attributes.VersionString == tag
		})
		log.Info(string(platform), " ", tag, " list builds")
		builds, _, err := client.Builds.ListBuilds(ctx, &asc.ListBuildsQuery{
			FilterApp:                       []string{appID},
			FilterPreReleaseVersionPlatform: []string{string(platform)},
		})
		if err != nil {
			return err
		}
		if len(builds.Data) == 0 {
			log.Fatal(string(platform), " ", tag, " no build found")
		}
		buildID := common.Ptr(builds.Data[0].ID)
		if version.ID == "" {
			log.Info(string(platform), " ", tag, " create version")
			newVersion, _, err := client.Apps.CreateAppStoreVersion(ctx, asc.AppStoreVersionCreateRequestAttributes{
				Platform:      platform,
				VersionString: tag,
			}, appID, buildID)
			if err != nil {
				return err
			}
			version = newVersion.Data

		} else {
			log.Info(string(platform), " ", tag, " check build")
			currentBuild, response, err := client.Apps.GetBuildIDForAppStoreVersion(ctx, version.ID)
			if err != nil {
				return err
			}
			if response.StatusCode != http.StatusOK || currentBuild.Data.ID != *buildID {
				switch *version.Attributes.AppStoreState {
				case asc.AppStoreVersionStatePrepareForSubmission,
					asc.AppStoreVersionStateRejected,
					asc.AppStoreVersionStateDeveloperRejected:
				case asc.AppStoreVersionStateWaitingForReview,
					asc.AppStoreVersionStateInReview,
					asc.AppStoreVersionStatePendingDeveloperRelease:
					submission, _, err := client.Submission.GetAppStoreVersionSubmissionForAppStoreVersion(ctx, version.ID, nil)
					if err != nil {
						return err
					}
					if submission != nil {
						log.Info(string(platform), " ", tag, " delete submission")
						_, err = client.Submission.DeleteSubmission(ctx, submission.Data.ID)
						if err != nil {
							return err
						}
						time.Sleep(5 * time.Second)
					}
				default:
					log.Fatal(string(platform), " ", tag, " unknown state ", string(*version.Attributes.AppStoreState))
				}
				log.Info(string(platform), " ", tag, " update build")
				response, err = client.Apps.UpdateBuildForAppStoreVersion(ctx, version.ID, buildID)
				if err != nil {
					return err
				}
				if response.StatusCode != http.StatusNoContent {
					response.Write(os.Stderr)
					log.Fatal(string(platform), " ", tag, " unexpected response: ", response.Status)
				}
			} else {
				switch *version.Attributes.AppStoreState {
				case asc.AppStoreVersionStatePrepareForSubmission,
					asc.AppStoreVersionStateRejected,
					asc.AppStoreVersionStateDeveloperRejected:
				case asc.AppStoreVersionStateWaitingForReview,
					asc.AppStoreVersionStateInReview,
					asc.AppStoreVersionStatePendingDeveloperRelease:
					continue
				default:
					log.Fatal(string(platform), " ", tag, " unknown state ", string(*version.Attributes.AppStoreState))
				}
			}
		}
		log.Info(string(platform), " ", tag, " list localization")
		localizations, _, err := client.Apps.ListLocalizationsForAppStoreVersion(ctx, version.ID, nil)
		if err != nil {
			return err
		}
		localization := common.Find(localizations.Data, func(it asc.AppStoreVersionLocalization) bool {
			return *it.Attributes.Locale == "en-US"
		})
		if localization.ID == "" {
			log.Info(string(platform), " ", tag, " no en-US localization found")
		}
		if localization.Attributes == nil || localization.Attributes.WhatsNew == nil || *localization.Attributes.WhatsNew == "" {
			log.Info(string(platform), " ", tag, " update localization")
			_, _, err = client.Apps.UpdateAppStoreVersionLocalization(ctx, localization.ID, &asc.AppStoreVersionLocalizationUpdateRequestAttributes{
				PromotionalText: common.Ptr("Yet another distribution for sing-box, the universal proxy platform."),
				WhatsNew:        common.Ptr(F.ToString("sing-box ", tag, ": Fixes and improvements.")),
			})
			if err != nil {
				return err
			}
		}
		log.Info(string(platform), " ", tag, " create submission")
	fixSubmit:
		for {
			_, response, err := client.Submission.CreateSubmission(ctx, version.ID)
			if err != nil {
				switch response.StatusCode {
				case http.StatusInternalServerError:
					continue
				default:
					return err
				}
			}
			switch response.StatusCode {
			case http.StatusCreated:
				break fixSubmit
			default:
				return err
			}
		}
	}
	return nil
}

func publishAppStore(ctx context.Context) error {
	tag, err := build_shared.ReadTag()
	if err != nil {
		return err
	}
	appID := requiredEnvironment("ASC_APP_ID")
	client := createClient(time.Minute)
	for _, platform := range []asc.Platform{
		asc.PlatformIOS,
		asc.PlatformMACOS,
		asc.PlatformTVOS,
	} {
		log.Info(string(platform), " list versions")
		versions, _, err := client.Apps.ListAppStoreVersionsForApp(ctx, appID, &asc.ListAppStoreVersionsQuery{
			FilterPlatform: []string{string(platform)},
		})
		if err != nil {
			return err
		}
		version := common.Find(versions.Data, func(it asc.AppStoreVersion) bool {
			return *it.Attributes.VersionString == tag
		})
		switch *version.Attributes.AppStoreState {
		case asc.AppStoreVersionStatePrepareForSubmission, asc.AppStoreVersionStateDeveloperRejected:
			log.Fatal(string(platform), " ", tag, " not submitted")
		case asc.AppStoreVersionStateWaitingForReview,
			asc.AppStoreVersionStateInReview:
			log.Warn(string(platform), " ", tag, " waiting for review")
			continue
		case asc.AppStoreVersionStatePendingDeveloperRelease:
		default:
			log.Fatal(string(platform), " ", tag, " unknown state ", string(*version.Attributes.AppStoreState))
		}
		_, _, err = client.Publishing.CreatePhasedRelease(ctx, common.Ptr(asc.PhasedReleaseStateComplete), version.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

func isRetryable(response *asc.Response) bool {
	if response == nil {
		return false
	}
	switch response.StatusCode {
	case http.StatusInternalServerError, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}
