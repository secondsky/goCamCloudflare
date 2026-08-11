/**
 * Token verification page (rendered as a string; no template engine).
 * This is the main age verification UI with webcam, selfie, scan ID sections.
 */
import { renderBase } from './base';

export interface TokenIndexOptions {
	js: {
		onDocumentReady: string;
		token: string;
		isLiveness: boolean;
		showDetectedAgeNumber: boolean;
		verificationTypeList: string[];
		verificationVersion: number;
		d: string | string[];
		sessionId: string;
		partnerColorConfig: any;
		ipCountry: string;
		deviceInfo: any;
		countryAgeMajority: Record<string, number>;
	};
	debug: boolean;
	cacheBuster: number;
}

export function renderTokenIndex(options: TokenIndexOptions): string {
	const { cacheBuster, debug } = options;

	const debugSection = debug ? `
		<div id="debugArea">
			<p>
				<strong>Debug:</strong>
				<a id="debugCloseButton">
					<i class="fa fa-times" aria-hidden="true"></i> Close
				</a>
			</p>
		</div>` : '';

	const content = `
	<div id="avsMainContainer" class="landscape">

		<a id="globalIframeCloseButton" class="isHidden">
			<i class="fa fa-times" aria-hidden="true"></i> Close
		</a>

		<div id="webCamAccessHelpArea" class="page layoutStaticPage isHidden">
			<div class="headerLogo">
				<img src="/static/img/logo.svg">
			</div>
			<h1 class="introHeading">Webcam access help</h1>
			<h2 class="introText">Webcam access it's allowed in different ways depending on your device platform</h2>
			<h2 class="introText">
				<strong class="layoutBiggerText"><i class="fa fa-android" aria-hidden="true"></i> Android chrome</strong>
			</h2>
			<h2 class="introText"><ol>
				<li>On your Android device, open the Chrome app.</li>
				<li>To the right of the address bar, tap More (triple dots) &gt; Settings &gt; Site Settings.</li>
				<li>Tap Microphone or Camera.</li>
				<li>Tap to turn the microphone or camera on or off.</li>
				<li>Look for go.cam under the Blocked list. If you see it BLOCKED, tap go.cam &gt; Access your camera &gt; Allow.</li>
				<li>Unblock BOTH camera and mic!</li>
			</ol></h2>
			<h2 class="introText">
				<strong class="layoutBiggerText"><i class="fa fa-apple" aria-hidden="true"></i> iOS Safari</strong>
			</h2>
			<h2 class="introText">
				<p><strong>Refresh the page</strong></p><ol>
				<li>Refresh the Safari tab</li>
				<li>You should be alerted for Microphone &amp; Camera Access</li>
				<li>Tap "Allow"</li>
			</ol>
				<p><strong>Make sure the camera access it's allowed</strong></p><ol>
				<li>Open the Settings app</li>
				<li>Tap on Safari &gt; Camera</li>
				<li>Scroll down to Camera &amp; Microphone</li>
				<li>Confirm that "Ask" or "Allow" is checked</li>
			</ol>
			</h2>
			<h2 class="introText">
				<strong class="layoutBiggerText"><i class="fa fa-chrome" aria-hidden="true"></i> Desktop chrome</strong>
			</h2>
			<h2 class="introText"><ol>
				<li>Click the camera icon - in your browsers address bar, top right</li>
				<li>Make sure that "Always allow" is selected</li>
				<li>Click done</li>
				<li>Refresh your browser</li>
			</ol></h2>
			<div class="submitArea">
				<a id="webCamAccessHelpBackButton" class="button layoutGreen">
					<i class="fa fa-chevron-left" aria-hidden="true"></i>Go Back
				</a>
			</div>
		</div>

		<div id="termsAndConditionsArea" class="page layoutStaticPage layoutTextBlock isHidden">
			<div class="headerLogo">
				<img src="/static/img/logo.svg">
			</div>
			<h1 class="introHeading">Terms and Conditions</h1>
			<p>If You are referred to GO.CAM by one of our Business Customers and wish to use Age-verification Solution rendered by GO.CAM, You are accepting these Terms and Conditions.</p>
			<div class="submitArea">
				<a id="termsAndConditionsBackButton" class="button layoutGreen">
					<i class="fa fa-chevron-left" aria-hidden="true"></i>Go Back
				</a>
			</div>
		</div>

		<div id="startPage" class="page layoutIntro">
			<div class="headerLogo">
				<img src="/static/img/logo.svg">
			</div>
			<h2 class="introText"><strong>Verify</strong> your <strong>age</strong> in a few <strong>easy</strong> steps</h2>
			<div class="selectionArea">
				<span class="label">Let's start by selecting a verification type:</span>
				<div class="iconArea" id="verificationTypeTabs">
					<div class="iconItem avsTab isSelected" data-type="selfie">
						<i class="iconImage">
							<svg><use xlink:href="/static/img/iconPack.svg#selfie" href="/static/img/iconPack.svg#selfie"></use></svg>
						</i>
						<div class="iconLabel">
							<span class="verificationTypeRadioButton"></span>
							<span class="iconDescription">Selfie age verification</span>
						</div>
					</div>
					<div class="iconItem avsTab" data-type="scanId">
						<i class="iconImage">
							<svg><use xlink:href="/static/img/iconPack.svg#scanId" href="/static/img/iconPack.svg#scanId"></use></svg>
						</i>
						<div class="iconLabel">
							<span class="verificationTypeRadioButton isSelected"></span>
							<span class="iconDescription">Scan id age verification</span>
						</div>
					</div>
				</div>
				<div class="termsArea" id="startPageTermsArea">
					<label>
						<input id="termsAndConditionsCheckbox" type="checkbox">I agree with the <a href="/terms/">terms and conditions</a>
					</label>
				</div>
				<div class="submitArea">
					<a id="startButton" class="button layoutGreen">
						<i class="fa fa-check" aria-hidden="true"></i>Start the verification
					</a>
				</div>
				<h2 class="introText">Don't worry, we neither store nor transmit any images or personal data from this detection.</h2>
				<h2 class="introText avsTabContent">We will locally capture a few webcam images on your device to estimate your age. You'll be asked to briefly change facial expressions. If unsuccessful, you may need to provide an official photo ID.</h2>
				<h2 class="introText avsTabContent isHidden">We will ask you to provide us with a <strong>image</strong> of your <strong>document</strong> or take <strong>a snapshot</strong> of it using your <strong>webcam</strong>. Your <strong>date of birth</strong> will be extracted in order to confirm your current age.</h2>
				<h2 class="introText layoutCertification">
					<span class="certificationColumn">
						<small class="certificationLabel">Certified by:</small>
						<span class="certificationImageList">
							<a href="https://www.kjm-online.de/pressemitteilungen/altersverifikation-persona-gocam/" target="_blank"><img src="/static/img/kjmLogo.jpg"></a>
							<a href="https://accscheme.com/registry/age-estimation/gsi-development-sas/" target="_blank"><img src="/static/img/accLogo.jpg"></a>
						</span>
					</span>
					<span class="certificationColumn">
						<small class="certificationLabel">Recommended by:</small>
						<span class="certificationImageList">
							<a href="https://www.asacp.org/" target="_blank"><img src="/static/img/asacpLogoWhiteBg.jpg"></a>
						</span>
					</span>
				</h2>
			</div>
		</div>

		<div id="faceApiPreloaderArea" class="preloader isHidden">
			<div id="faceApiPreloaderTextArea">
				<i class="fa fa-spinner fa-spin" aria-hidden="true"></i> Preloading verification resources:
			</div>
			<div id="faceApiPreloaderPercentArea" class="counter">100%</div>
		</div>

		<div id="tesseractPreloaderArea" class="preloader isHidden">
			<div id="tesseractPreloaderTextArea">
				<i class="fa fa-spinner fa-spin" aria-hidden="true"></i> Preloading verification resources:
			</div>
			<div id="tesseractPreloaderPercentArea" class="counter"></div>
		</div>

		<div id="errorMessageArea" class="page layoutError isHidden">
			<div class="headerLogo"><img src="/static/img/logo.svg"></div>
			<h1 class="introHeading isHidden"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i>Error</h1>
			<h2 class="introText" id="errorMessageTextArea"></h2>
			<h2 class="introText isHidden" id="errorMessageAdditionalTextArea"></h2>
			<h2 class="introText" id="errorMessageQrTextArea">Or, <strong>continue verification on your mobile</strong> by scanning the QR code below. Make sure you <strong>keep this window open</strong> while using your mobile.</h2>
			<div id="startPageErrorQrCode" class="qrCodeArea"></div>
			<div class="submitArea">
				<a id="errorMessageStartOverButton" class="button layoutRed">
					<i class="fa fa-refresh" aria-hidden="true"></i>Try again
				</a>
			</div>
		</div>

		<div id="selfieAgeDetectionIntro" class="page layoutIntro isHidden">
			<div class="headerLogo"><img src="/static/img/logo.svg"></div>
			<div class="introIcon"><img src="/static/img/selfie-icon.svg"></div>
			<h1 class="introHeading">Selfie age verification:</h1>
			<h2 class="introText">We will analyze your <strong>selfie</strong>, make sure you look into the <strong>camera</strong> and your <strong>face</strong> it's <strong>visible</strong> and <strong>centered</strong> as much as possible:</h2>
			<div class="introText"><p class="layoutRedText">No data, no videos and no pictures are sent to our servers</p></div>
			<div id="selfieAgeDetectionDeviceAccessArea" class="informationArea layoutBlack layoutRelative layoutLoading">
				<div class="loadingArea"><i class="fa fa-spinner fa-spin" aria-hidden="true"></i><strong>Detection in progress:</strong></div>
				<div class="statusArea">Please allow your camera access in order to continue</div>
			</div>
			<div id="selfieAgeDetectionDeviceSelectionArea" class="isHidden">
				<div class="selectionArea">
					<span class="label">Please select a camera to use:</span>
					<select id="selfieAgeDetectionDeviceSelect" class="js-example-basic-single select"></select>
				</div>
			</div>
			<div id="selfieAgeDetectionSubmitArea" class="isHidden">
				<div class="submitArea">
					<a id="selfieAgeDetectionStartButton" class="button layoutGreen">Continue <i class="fa fa-arrow-circle-right" aria-hidden="true"></i></a>
					<a id="selfieAgeDetectionCancelButton" class="linkButton">Cancel</a>
				</div>
			</div>
			<h2 class="introText layoutCertification">
				<span class="certificationColumn">
					<small class="certificationLabel">Certified by:</small>
					<span class="certificationImageList">
						<a href="https://www.kjm-online.de/pressemitteilungen/altersverifikation-persona-gocam/" target="_blank"><img src="/static/img/kjmLogo.jpg"></a>
						<a href="https://accscheme.com/registry/age-estimation/gsi-development-sas/" target="_blank"><img src="/static/img/accLogo.jpg"></a>
					</span>
				</span>
				<span class="certificationColumn">
					<small class="certificationLabel">Recommended by:</small>
					<span class="certificationImageList">
						<a href="https://www.asacp.org/" target="_blank"><img src="/static/img/asacpLogoWhiteBg.jpg"></a>
					</span>
				</span>
			</h2>
		</div>

		<div id="selfieAgeDetectionPage" class="page layoutDetection isHidden">
			<div class="videoOverlay">
				<div class="brightness-indicator" id="brightnessIndicatorArea">
					<div class="ios-slider">
						<i class="fa fa-moon-o icon-moon" aria-hidden="true"></i>
						<div class="slider-track"><div class="slider-fill"><i class="fa fa-angle-up icon-chevron" aria-hidden="true"></i><i class="fa fa-angle-up icon-chevron" aria-hidden="true"></i></div></div>
						<i class="fa fa-sun-o icon-sun" aria-hidden="true"></i>
					</div>
				</div>
			</div>
			<div id="selfieVideoContainer" class="videoSource">
				<video id="selfieVideo" autoplay="" muted="" playsinline=""></video>
				<canvas id="selfieVideoOverlayCanvas" class="overlayCanvas"></canvas>
				<canvas id="selfieVideoResultCanvas" class="resultCanvas"></canvas>
			</div>
			<div class="maskGuidContainer">
				<div id="faceGuide" class="maskGuide layoutFace">
					<div class="statusMessageArea">
						<div id="faceGuideAgeArea" class="ageGuideArea">
							<p><span id="selfieAgeDetectionCurrentAgeArea"></span></p>
							<p><span id="selfieAgeDetectionAverageAgeArea"></span></p>
						</div>
						<div id="faceGuideSmileStartHintArea" class="isHidden">
							<p class="emoticonArea"><i class="fa fa-meh-o" aria-hidden="true"></i><i class="fa fa-arrow-right layoutSmallerEmoticon" aria-hidden="true"></i><i class="fa fa-smile-o" aria-hidden="true"></i></p>
							<p class="hintArea" id="faceGuideSmileStartHintLabel">Please smile</p>
						</div>
						<div id="faceGuideSmileStopHintArea" class="isHidden">
							<p class="emoticonArea"><i class="fa fa-smile-o" aria-hidden="true"></i><i class="fa fa-arrow-right layoutSmallerEmoticon" aria-hidden="true"></i><i class="fa fa-meh-o" aria-hidden="true"></i></p>
							<p class="hintArea" id="faceGuideSmileStopHintLabel">Please stop smiling</p>
						</div>
						<div class="statusArea isHidden" id="selfieAgeDetectionStatusLabel"></div>
						<div class="loadingIconArea">
							<i class="fa fa-spinner fa-spin" aria-hidden="true"></i>
							<span class="loadingProgressBarContainer" id="faceGuideLoadingProgressBar"><span class="loadingProgressBar"></span></span>
						</div>
					</div>
				</div>
			</div>
			<div class="informationArea layoutTransparent">
				<div class="loadingArea">
					<strong>
						<span id="selfieAgeDetectionLoadingLabelArea"></span>
						<span id="selfieAgeDetectionLoadingLabelPercentCounter"></span>
					</strong>
				</div>
			</div>
		</div>

		<div id="scanIdAgeVerificationIntro" class="page layoutIntro isHidden">
			<div class="headerLogo"><img src="/static/img/logo.svg"></div>
			<div class="introIcon"><img src="/static/img/scanid-icon.svg"></div>
			<h1 class="introHeading">Scan id age verification</h1>
			<h2 class="introText">We will analyze your <strong>document</strong>, make sure the document it's <strong>contained</strong> within the <strong>marked area</strong> on the screen</h2>
			<div class="documentHelperArea" id="scanIdAgeVerificationDocumentHelperArea"></div>
			<div id="scanIdAgeVerificationDeviceAccessArea" class="informationArea layoutBlack layoutRelative">
				<div class="loadingArea"><i class="fa fa-spinner fa-spin" aria-hidden="true"></i><strong>Detection in progress</strong></div>
				<div class="statusArea">Please allow your camera access in order to continue</div>
			</div>
			<div id="scanIdAgeVerificationDeviceSelectionArea" class="isHidden">
				<div class="selectionArea">
					<span class="label">Please select a camera to use:</span>
					<select id="scanIdAgeVerificationDeviceSelect" class="js-example-basic-single select"></select>
				</div>
			</div>
			<div id="scanIdAgeVerificationSubmitArea" class="isHidden">
				<div class="selectionArea">
					<span class="label">Country of issue of your identity document:</span>
					<select id="scanIdAgeVerificationCountrySelect" class="js-example-basic-single select"></select>
				</div>
				<div id="scanIdAgeVerificationStateArea" class="selectionArea">
					<span class="label">State of issue of your identity document:</span>
					<select id="scanIdAgeVerificationStateSelect" class="js-example-basic-single select"></select>
				</div>
				<div id="scanIdAgeVerificationTypeArea" class="selectionArea">
					<span class="label">Please select your id type:</span>
					<select id="scanIdAgeVerificationTypeSelect" class="js-example-basic-single select"></select>
				</div>
				<div class="browseArea isHidden">
					<i id="scanIdAgeVerificationUploadImageIntroButton" class="fa fa-cloud-upload icon" aria-hidden="true"></i>
					<span class="text">Browse image</span>
				</div>
				<input type="file" accept="image/*" class="isHidden" id="scanIdAgeVerificationUploadFileIntroInput">
				<div class="submitArea">
					<a id="scanIdAgeDetectionStartButton" class="button layoutGreen">Continue <i class="fa fa-arrow-circle-right" aria-hidden="true"></i></a>
					<a id="scanIdAgeDetectionCancelButton" class="linkButton">Cancel</a>
				</div>
			</div>
		</div>

		<div id="scanIdAgeVerificationPage" class="page layoutDetection isHidden">
			<div class="videoMirrorContainer">
				<a id="videoMirrorButton"><i class="fa fa-refresh" aria-hidden="true"></i></a>
			</div>
			<div id="ratioRecommendArea" class="page layoutHint isHidden">
				<h1 class="introHeading"><i class="fa fa-asterisk" aria-hidden="true"></i>Performance hint</h1>
				<h2 class="introText" id="ratioRecommendTextArea"></h2>
				<div class="submitArea"><a id="ratioRecommendButton" class="button"><i class="fa fa-check" aria-hidden="true"></i>OK</a></div>
			</div>
			<div id="scanIdAgeVerificationDocumentProcessingArea" class="page layoutDocumentProcessing isHidden">
				<div class="imageContainer" id="documentProcessingCanvasContainer">
					<div class="loadingOverlay" id="documentProcessingCanvasLoadingOverlayArea">
						<span><i class="fa fa-spinner fa-spin" aria-hidden="true"></i></span>
					</div>
					<canvas id="documentProcessingCanvas" class="documentProcessingCanvas"></canvas>
					<canvas id="documentProcessingCanvasOverlay" class="documentProcessingCanvasOverlay"></canvas>
				</div>
				<div id="scanIdAgeVerificationDocumentProcessingConfirmationArea" class="confirmationArea isHidden">
					<div class="introText">Are you sure you want to <strong>continue</strong> using the document <strong>photo above</strong>?</div>
					<div class="submitArea">
						<a class="button layoutGreen" id="scanIdAgeVerificationConfirmationYesButton">Yes, it looks good <i class="fa fa-arrow-circle-right" aria-hidden="true"></i></a>
						<a class="button layoutRed" id="scanIdAgeVerificationConfirmationNoButton">No, use another photo <i class="fa fa-refresh" aria-hidden="true"></i></a>
					</div>
					<div class="introText">
						<p><strong><i class="fa fa-info-circle" aria-hidden="true"></i>Hint</strong></p>
						<p>For a better detection, make sure the document in the photo it's not rotated, blurry and the light conditions are good</p>
					</div>
				</div>
				<div id="scanIdAgeVerificationDocumentProcessingProcessArea" class="processArea isHidden">
					<div class="introText"><strong>Processing</strong> your document, <strong>please wait</strong> for all the steps <strong>to complete</strong></div>
					<div class="checkOutList">
						<div class="checkOutItem">
							<span class="text">Initializing detection libraries - <span id="scanIdAgeVerificationLoadingLabelPercentCounter"></span></span>
							<span class="status"><span id="scanIdAgeVerificationLoadingLibraryButton"><i class="fa fa-check statusIcon" aria-hidden="true"></i></span></span>
						</div>
						<div class="checkOutItem" id="scanIdAgeVerificationFaceSimilarityArea">
							<span class="text">Checking document face similarity</span>
							<span class="status"><span class="status"><span id="scanIdAgeVerificationFaceSimilarityButton"><i class="fa fa-check statusIcon" aria-hidden="true"></i></span></span></span>
						</div>
						<div class="checkOutItem">
							<span class="text">Extracting birth date</span>
							<span class="status"><span class="status"><span id="scanIdAgeVerificationBirthDateButton"><i class="fa fa-check statusIcon" aria-hidden="true"></i></span></span></span>
						</div>
					</div>
				</div>
			</div>
			<div class="videoOverlay"></div>
			<div id="scanIdVideoContainer" class="videoSource">
				<video id="scanIdVideo" autoplay="" muted="" playsinline=""></video>
				<canvas id="scanIdVideoOverlayCanvas" class="overlayCanvas"></canvas>
				<canvas id="scanIdVideoResultCanvas" class="resultCanvas"></canvas>
			</div>
			<div class="maskGuidContainer">
				<div id="idCardGuide" class="maskGuide layoutIdentityCardGeneric"></div>
				<div id="idCardGuideBirthDate" class="maskGuideField"></div>
			</div>
			<div class="informationArea layoutTransparent layoutNoTop">
				<div class="imageCaptureArea">
					<div class="captureOption" id="scanIdAgeVerificationTakePhotoButton">
						<i class="fa fa-camera icon" aria-hidden="true"></i>
						<span class="text">Take a photo</span>
					</div>
					<div class="captureOption" id="scanIdAgeVerificationUploadImageButton">
						<i class="fa fa-cloud-upload icon" aria-hidden="true"></i>
						<span class="text">Browse image</span>
					</div>
					<input type="file" accept="image/*" class="isHidden" id="scanIdAgeVerificationUploadFileInput">
				</div>
				<div class="statusArea">Take a photo of your document or browse an existing image</div>
			</div>
		</div>

		<div id="creditCardVerificationIntro" class="page layoutIntro isHidden">
			<div class="headerLogo"><img src="/static/img/logo.svg"></div>
			<div class="introIcon"><img src="/static/img/creditcard-icon.svg"></div>
			<h1 class="introHeading">Credit card age verification</h1>
			<h2 class="introText">
				<strong>Verify your age</strong> by using, your <strong>credit card</strong>. By clicking <strong>the button bellow</strong> a new <strong>pop-up window</strong> will open a <strong>secure endpoint</strong> where your credentials will be verified.
			</h2>
			<div class="submitArea">
				<a id="creditCardAgeDetectionStartButton" class="button layoutGreen">Continue <i class="fa fa-arrow-circle-right" aria-hidden="true"></i></a>
				<a id="creditCardAgeDetectionCancelButton" class="linkButton">Cancel</a>
			</div>
		</div>

		<div id="resultPageSuccess" class="page layoutResult layoutSuccess isHidden">
			<div class="headerLogo"><img src="/static/img/logo.svg"></div>
			<div class="introIcon layoutFontIcon layoutGreen"><i class="fa fa-check" aria-hidden="true"></i></div>
			<h1 class="introHeading">Verification complete</h1>
			<h2 class="introText">Information stored locally on your device are now deleted</h2>
			<h2 class="introText">Your <strong>age</strong> has been <strong>verified</strong>, go <strong>back to your account</strong> using the button below</h2>
			<h2 class="introText" id="resultPageSuccessSelfieArea"></h2>
			<h2 class="introText" id="resultPageSuccessScanIdArea"></h2>
			<div class="submitArea">
				<a id="resultSuccessButton" class="button layoutGreen">
					<i class="fa fa-check" aria-hidden="true"></i>Back to the main site
				</a>
			</div>
		</div>

		<div id="resultPageFail" class="page layoutResult layoutFail isHidden">
			<div class="headerLogo"><img src="/static/img/logo.svg"></div>
			<h1 class="introHeading">Verification failed</h1>
			<h2 class="introText">Information stored locally on your device are now deleted</h2>
			<h2 class="introText" id="resultPageFailReasonArea"></h2>
			<h2 class="introText" id="resultPageFailQrArea">Or, <strong>continue verification on your mobile</strong> by scanning the QR code below. Make sure you <strong>keep this window open</strong> while using your mobile.</h2>
			<div id="failPageErrorQrCode" class="qrCodeArea"></div>
			<div class="submitArea">
				<a id="resultFailButton" class="button layoutRed">
					<i class="fa fa-refresh" aria-hidden="true"></i>Start over
				</a>
			</div>
		</div>
		${debugSection}
	</div>`;

	const javascript = `
<script type="text/javascript" crossorigin="anonymous" src="/static/js/vendor/jquery-3.5.1.min.js"></script>
<script type="text/javascript" crossorigin="anonymous" src="/static/js/vendor/adapter-7.6.4/adapter.js"></script>
<script type="text/javascript" crossorigin="anonymous" src="/static/js/vendor/face-api-1.7.12/face-api.js"></script>
<script type="text/javascript" crossorigin="anonymous" src='/static/js/vendor/tesseract-js-2.1.1/tesseract.min.js'></script>
<script type="text/javascript" crossorigin="anonymous" src='/static/js/vendor/js-base64-3.5.2/base64.min.js'></script>
<script type="text/javascript" crossorigin="anonymous" src='/static/js/vendor/qr-code/v1ncc/qr.min.js?v1'></script>

<script type="text/javascript" crossorigin="anonymous" src="/static/js/app/avs.js?${cacheBuster}"></script>
<script type="text/javascript" crossorigin="anonymous" src="/static/js/app/avsFactory.js?${cacheBuster}"></script>
<script type="text/javascript" crossorigin="anonymous" src="/static/js/app/common.js?${cacheBuster}"></script>`;

	return renderBase({
		content,
		javascript,
		js: options.js,
		cacheBuster,
	});
}
