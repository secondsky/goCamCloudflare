/**
 * Iframe embed check page (rendered as a string; no template engine)
 */

export interface EmbedCheckOptions {
	js: {
		isAgeVerified: boolean;
		verificationPayload: string | null;
	};
	cacheBuster: number;
}

export function renderTokenEmbedCheck(options: EmbedCheckOptions): string {
	const jsDataJson = JSON.stringify(options.js)
		.replace(/</g, '\\u003c')
		.replace(/\u2028/g, '\\u2028')
		.replace(/\u2029/g, '\\u2029');

	return `<!DOCTYPE HTML>
<html lang="en" xml:lang="en">
<head>
	<meta name="robots" content="noindex">
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<script id="app-data" type="application/json">${jsDataJson}</script>

</head>
<body style="background: transparent">
<div>
</div>

	<script type="text/javascript" crossorigin="anonymous" src="/static/js/app/avsFactoryIframeCheck.js?${options.cacheBuster}"></script>

</body>
</html>`;
}
