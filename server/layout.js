const html = require('choo/html');
const assets = require('../common/assets');
const initScript = require('./initScript');

module.exports = function(state, body = '') {
  const firaTag = state.fira
    ? html`
        <link
          rel="stylesheet"
          type="text/css"
          href="https://code.cdn.mozilla.net/fonts/fira.css"
        />
      `
    : '';
  return html`
    <!DOCTYPE html>
    <html lang="${state.locale}">
      <head>
        <base href="/" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />

        <meta property="og:title" content="${state.title}" />
        <meta name="twitter:title" content="${state.title}" />
        <meta name="description" content="${state.description}" />
        <meta property="og:description" content="${state.description}" />
        <meta name="twitter:description" content="${state.description}" />
        <meta name="twitter:card" content="summary" />
        <meta
          property="og:image"
          content="${state.baseUrl}${assets.get('send-fb.jpg')}"
        />
        <meta
          name="twitter:image"
          content="${state.baseUrl}${assets.get('send-twitter.jpg')}"
        />
        <meta property="og:url" content="${state.baseUrl}" />
        <meta name="theme-color" content="#0a84ff" />
        <link rel="manifest" href="/app.webmanifest" />

        <title>${state.title}</title>

        <link
          rel="stylesheet"
          type="text/css"
          href="${assets.get('app.css')}"
        />

        <!-- generic favicons -->
        <link rel="icon" href="${assets.get('favicon-32.png')}" sizes="32x32" />
        <link rel="icon" href="${assets.get('favicon-96.png')}" sizes="96x96" />
        <link
          rel="icon"
          href="${assets.get('favicon-128.png')}"
          sizes="128x128"
        />
        <link
          rel="icon"
          href="${assets.get('favicon-228.png')}"
          sizes="228x228"
        />

        <!-- Android -->
        <link
          rel="shortcut icon"
          href="${assets.get('favicon-196.png')}"
          sizes="196x196"
        />

        <!-- iOS -->
        <link
          rel="apple-touch-icon"
          href="${assets.get('favicon-120.png')}"
          sizes="120x120"
        />
        <link
          rel="apple-touch-icon"
          href="${assets.get('favicon-152.png')}"
          sizes="152x152"
        />
        <link
          rel="apple-touch-icon"
          href="${assets.get('favicon-180.png')}"
          sizes="180x180"
        />

        <!-- Windows 8 IE 10 -->
        <meta name="msapplication-TileColor" content="#FFFFFF" />
        <meta
          name="msapplication-TileImage"
          content="${assets.get('favicon-144.png')}"
        />

        <!-- Windows 8.1 + IE11 and above -->
        <meta name="msapplication-config" content="/browserconfig.xml" />

        ${firaTag}
        <script defer src="${assets.get('app.js')}"></script>
      </head>
      <noscript>
        <div class="noscript">
          <h2>${state.translate('javascriptRequired')}</h2>
          <p>
            <a
              class="link"
              href="https://github.com/mozilla/send/blob/master/docs/faq.md#why-does-firefox-send-require-javascript"
            >
              ${state.translate('whyJavascript')}
            </a>
          </p>
          <p>${state.translate('enableJavascript')}</p>
        </div>
      </noscript>
      ${body} ${initScript(state)}
    </html>
  `;
};
