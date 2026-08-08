/**
 * Base HTML template — replaces base.twig.
 * Produces the <!DOCTYPE>, <head>, and <body> skeleton.
 */

export interface BaseTemplateOptions {
	head?: string;
	content: string;
	javascript?: string;
	js?: Record<string, any>;
	cacheBuster?: number;
}

export function renderBase(options: BaseTemplateOptions): string {
	const { head = '', content, javascript = '', js = {} } = options;

	const jsDataJson = JSON.stringify(js)
		.replace(/</g, '\\u003c')
		.replace(/\u2028/g, '\\u2028')
		.replace(/\u2029/g, '\\u2029');

	return `<!DOCTYPE HTML>
<html lang="en" xml:lang="en">
<head>
	<meta name="robots" content="noindex">
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no">
	<title>Go.cam demo</title>
	<meta name="description" content="Age verification system - demo">

	${head}

	<link rel="stylesheet" href="/static/css/main.css">
	<link rel="stylesheet" href="/static/css/vendor/font-awesome-4.7.0/css/font-awesome.min.css">
	<link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;700&display=swap" rel="stylesheet">

	<script id="app-data" type="application/json">${jsDataJson}</script>

</head>
<body>
	${content}

	${javascript}
</body>
</html>`;
}
