/**
 * Home page template — replaces home/index.twig.
 * The HTML content is the exact same as the original Twig template,
 * with Twig syntax replaced by JS template interpolation.
 */
import { renderBase } from './base';

export interface HomeTemplateOptions {
	js: {
		onDocumentReady: string;
	};
	cacheBuster: number;
	nodeEnv?: string;
}

export function renderHome(options: HomeTemplateOptions): string {
	const { cacheBuster, nodeEnv = 'production' } = options;

	const head = `
	<link rel="stylesheet" href="/static/css/vendor/bootstrap-5.0.2/bootstrap.min.css">`;

	const javascript = `
	<script type="text/javascript" crossorigin="anonymous" src="/static/js/vendor/jquery-3.5.1.min.js"></script>
	<script type="text/javascript" crossorigin="anonymous" src="/static/js/vendor/bootstrap-5.0.2/bootstrap.min.js"></script>

	<script type="text/javascript" crossorigin="anonymous" src="/static/js/app/common.js?${cacheBuster}"></script>
	<script type="text/javascript" crossorigin="anonymous" src="/static/js/app/avsFactoryIframeSdk.js?${cacheBuster}"></script>`;

	const content = `
	<div id="staticPage">

		<div class="headerContainer">
			<div class="headerTop">
				<div class="headerLogoArea">
					<a href="/">
						<img src="/static/img/logo.svg?20240507-12">
					</a>
				</div>
			</div>
		</div>
		<div class="headerHeroImage">
			<div class="heroHeadingContainer">
				<h1 class="heroHeading"><strong>Age</strong> <strong>verification</strong> system</h1>
				<p class="heroSubHeading">Made easy</p>
			</div>
			<img class="heroImage" src="/static/img/heroHeader.jpg">
		</div>

		<div class="clear"></div>

		<div id="avsPage">
			<div class="container">
				<div class="ageVerificationSolution">

					<div id="accessInformation" class="card accessInformation mb-3">
						<!-- access keys -->
						<div class="card-header">
							<i class="fa fa-key m-1"></i> Configuration
						</div>
						<div class="card-body">
							<div id="accessInformationContentArea" class="">
								<form>
									<div class="form-group mb-3">
										<label for="accessInformationCallbackUrlInput" class="form-label">Verification result callback url:</label>
										<input id="accessInformationCallbackUrlInput" class="form-control" type="text" value="http://localhost:3300/callback">
									</div>
								</form>

							</div>
						</div>
					</div>

					<div id="accessSection" class="accessSection">

						<div id="exampleImplementation" class="card accessInformation mb-3">
							<div class="card-header">
								<i class="fa fa-check m-1"></i> Example implementation
							</div>
							<div class="card-body">
								<h5 class="layoutPaddingBottom">
									<strong>Color theme</strong>
								</h5>

								<div class="colorInputArea mb-3">
									<p>
										<strong>Body area</strong>
									</p>

									<form class="row mb-3">
										<div class="col-md-4 col-lg-3">
											<div class="form-group">
												<label for="colorConfigBodyBackgroundInput">Background</label>
												<input type="color" id="colorConfigBodyBackgroundInput" class="form-control form-control-color" value="#ffffff">
											</div>
										</div>
										<div class="col-md-4 col-lg-3">
											<div class="form-group">
												<label for="colorConfigBodyForegroundInput">Foreground</label>
												<input type="color" id="colorConfigBodyForegroundInput" class="form-control form-control-color" value="#000000">
											</div>
										</div>
									</form>

									<p>
										<strong>Buttons</strong>
									</p>

									<form class="row mb-3">
										<div class="col-md-4 col-lg-3">
											<div class="form-group">
												<label for="colorConfigButtonBackgroundInput">Background</label>
												<input type="color" id="colorConfigButtonBackgroundInput" class="form-control form-control-color" value="#9acd1f">
											</div>
										</div>
										<div class="col-md-4 col-lg-3">
											<div class="form-group">
												<label for="colorConfigButtonForegroundInput">Foreground</label>
												<input type="color" id="colorConfigButtonForegroundInput" class="form-control form-control-color" value="#ffffff">
											</div>
										</div>
										<div class="col-md-4 col-lg-3">
											<div class="form-group">
												<label for="colorConfigButtonForegroundCTAInput">Foreground call to action</label>
												<input type="color" id="colorConfigButtonForegroundCTAInput" class="form-control form-control-color" value="#ffffff">
											</div>
										</div>
									</form>
								</div>

								<h5 class="layoutPaddingBottom">
									<strong>Verify age using a redirect</strong>
								</h5>
								<p>
									By clicking the button below a new browser tab will open with the age verification page using your config data above.
									The verification result will be posted back to your <strong>verification result callback url</strong> if it's already defined.
								</p>
								<p>
									<button id="exampleImplementationStartRedirectButton" class="btn btn-success btn-sm layoutAgeVerification">
										<i class="fa fa-eye"></i> Start age verification
									</button>
								</p>

								<h5 class="layoutPaddingBottom">
									<strong>Verify age using the iframe</strong>
								</h5>
								<p>
									By clicking the button below a screen overlay will open with the age verification page using your config data above.
									The verification result will be posted back to your <strong>verification result callback url</strong> if it's already defined.
									Since we are using the javascript implementation, we will also listen to the <strong>events</strong> we receive while the detection it's running and <strong>we will log it in the area below</strong>.
								</p>

								<form>
									<div class="form-group mb-3">
										<label for="ageVerificationLogTextarea" class="form-label">Age verification log:</label>
										<textarea id="ageVerificationLogTextarea" class="form-control" readonly="" rows="7"></textarea>
									</div>
									<div class="form-group">
										<button id="exampleImplementationStartJsButton" class="btn btn-success btn-sm layoutAgeVerification mb-2">
											<i class="fa fa-eye"></i> Start age verification
										</button>
										<button id="exampleImplementationIframeJsButton" class="btn btn-success btn-sm layoutAgeVerification mb-2" disabled="disabled">
											<i class="fa fa-plus"></i> Open verification iframe
										</button>
									</div>
								</form>

							</div>
						</div>

						<div id="implementationGuide" class="card implementationGuide">
							<div class="card-header">
								<i class="fa fa-info m-1"></i> Implementation guide
							</div>
							<div class="card-body">
								<div class="accordion" id="accordion">
									<div class="accordion-item">
										<div class="accordion-header" id="verificationTypesItem">
											<button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#collapseVerificationTypesItem" aria-expanded="false" aria-controls="collapseVerificationTypesItem">
												Verification types
											</button>
										</div>
										<div id="collapseVerificationTypesItem" class="collapse" aria-labelledby="verificationTypesItem" data-bs-parent="#accordion">
											<div class="accordion-body">
												<p>Please refer to the <a href="https://github.com/Godotcam/goCamOpenSource" target="_blank">project documentation</a> for detailed verification type descriptions.</p>
											</div>
										</div>
									</div>

									<div class="accordion-item">
										<div class="accordion-header" id="implementationDetailsItem">
											<button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#collapseImplementationDetailsItem" aria-expanded="false" aria-controls="collapseImplementationDetailsItem">
												Implementation details
											</button>
										</div>
										<div id="collapseImplementationDetailsItem" class="collapse" aria-labelledby="implementationDetailsItem" data-bs-parent="#accordion">
											<div class="accordion-body">
												<p>Please refer to the <a href="https://github.com/Godotcam/goCamOpenSource" target="_blank">project documentation</a> for implementation details and API reference.</p>
											</div>
										</div>
									</div>

									<div class="accordion-item">
										<div class="accordion-header" id="frontEndEventInformationItem">
											<button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#collapseFrontEndEventInformationItem" aria-expanded="false" aria-controls="collapseFrontEndEventInformationItem">
												Frontend event information
											</button>
										</div>
										<div id="collapseFrontEndEventInformationItem" class="collapse" aria-labelledby="frontEndEventInformationItem" data-bs-parent="#accordion">
											<div class="accordion-body">
												<p>Please refer to the <a href="https://github.com/Godotcam/goCamOpenSource" target="_blank">project documentation</a> for frontend event details.</p>
											</div>
										</div>
									</div>

									<div class="accordion-item">
										<div class="accordion-header" id="verificationResultCallbackItem">
											<button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#collapseVerificationResultCallbackItem" aria-expanded="false" aria-controls="collapseVerificationResultCallbackItem">
												Verification result callback url information
											</button>
										</div>
										<div id="collapseVerificationResultCallbackItem" class="collapse" aria-labelledby="verificationResultCallbackItem" data-bs-parent="#accordion">
											<div class="accordion-body">
												<p>Please refer to the <a href="https://github.com/Godotcam/goCamOpenSource" target="_blank">project documentation</a> for callback details.</p>
											</div>
										</div>
									</div>
								</div>
							</div>
						</div>

					</div>
				</div>
			</div>
		</div>

	</div>
	<div class="clear"></div>
	<p>&nbsp;</p>
	<p class="text-center"><small>Node env: ${escapeHtml(nodeEnv)}</small></p>`;

	return renderBase({
		head,
		content,
		javascript,
		js: options.js,
		cacheBuster,
	});
}

function escapeHtml(str: string): string {
	return str
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}
