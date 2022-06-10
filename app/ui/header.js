/* global AUTH_CONFIG */

const html = require('choo/html');
const Component = require('choo/component');
const Account = require('./account');
const assets = require('../../common/assets');
const { platform } = require('../utils');

class Header extends Component {
  constructor(name, state, emit) {
    super(name);
    this.state = state;
    this.emit = emit;
    this.account = state.cache(Account, 'account');
  }

  update() {
    this.account.render();
    return false;
  }
  createElement() {
    const title =
      platform() === 'android'
        ? html`
          <h1 class="text-3xl font-bold md:pb-2">Send</h1>
          `
        : html`
            <a class="flex flex-row items-center" href="/">
              <h1 class="text-3xl font-bold md:pb-2">Send</h1>
            </a>
          `;
    return html`
      <header
        class="main-header relative flex-none flex flex-row items-center justify-between w-full px-6 md:px-8 h-16 md:h-24 z-20 bg-transparent"
      >
        ${title} ${this.account.render()}
      </header>
    `;
  }
}

module.exports = Header;
