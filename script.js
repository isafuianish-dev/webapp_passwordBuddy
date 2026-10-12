
(function () {
  'use strict';

  var APP_KEY = 'webapp_passwordBuddy';
  var themeBtn = document.getElementById('btnTheme');
  var motionBtn = document.getElementById('btnMotion');
  var browseAppsBtn = document.getElementById('btnBrowseApps');
  var goHomeBtn = document.getElementById('btnGoHome');

  var MOTION_ORDER = ['system', 'on', 'reduced'];
  var MOTION_ICON_NAMES = { on: 'zap', reduced: 'pause', system: 'restore' };
  var MOTION_LABELS = { on: 'On', reduced: 'Reduced', system: 'System' };

  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  function currentMotion() {
    return Buddy.theme.currentMotionMode();
  }

  function render() {
    var dark = currentTheme() === 'dark';
    themeBtn.innerHTML = dark ? Buddy.ICONS.sun : Buddy.ICONS.moon;
    browseAppsBtn.innerHTML = Buddy.ICONS.grid;
    goHomeBtn.innerHTML = Buddy.ICONS.house;

    var mode = currentMotion();
    motionBtn.innerHTML = mode === 'on' ? Buddy.ICONS.zap : Buddy.icon(MOTION_ICON_NAMES[mode]);
    motionBtn.title = 'Motion: ' + MOTION_LABELS[mode];
    motionBtn.setAttribute('aria-label', 'Motion: ' + MOTION_LABELS[mode] + ' (click to change)');
  }

  themeBtn.addEventListener('click', function () {
    Buddy.theme.applyTheme(APP_KEY, currentTheme() === 'dark' ? 'light' : 'dark');
    render();
  });

  motionBtn.addEventListener('click', function () {
    var next = MOTION_ORDER[(MOTION_ORDER.indexOf(currentMotion()) + 1) % MOTION_ORDER.length];
    Buddy.theme.applyMotion(next);
    render();
  });

  render();
})();
