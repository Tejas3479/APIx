/* APIx shared UI behaviors.
 *
 * Progressive enhancement only — every behavior is a no-op if the page does
 * not opt in. The `html` element gets a `.js` class early (set inline on each
 * page) so CSS can gate reveal animations behind `html.js`.
 */

(function () {
  'use strict';

  // Progressive enhancement marker: CSS gates reveal animations behind
  // `html.js` so no-JS users always see content.
  document.documentElement.classList.add('js');

  /* ── Dark mode controller (shared across all pages) ── */
  function updateThemeUI(dark) {
    document.querySelectorAll('#themeToggle, .btn-theme-toggle').forEach((btn) => {
      const sun = btn.querySelector('.icon-sun');
      const moon = btn.querySelector('.icon-moon');
      if (sun && moon) {
        sun.style.display = dark ? 'block' : 'none';
        moon.style.display = dark ? 'none' : 'block';
      }
    });
  }

  function applyTheme(dark) {
    document.documentElement.classList.toggle('dark', dark);
    updateThemeUI(dark);
    try {
      localStorage.setItem('theme', dark ? 'dark' : 'light');
    } catch (e) {}
  }

  // Initialize theme from localStorage or system preference
  let isDark = false;
  try {
    const saved = localStorage.getItem('theme');
    isDark = saved ? saved === 'dark' : (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  } catch (e) {
    isDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }
  applyTheme(isDark);

  document.addEventListener('DOMContentLoaded', () => {
    updateThemeUI(document.documentElement.classList.contains('dark'));
  });

  document.addEventListener('click', (e) => {
    const toggle = e.target.closest('#themeToggle, .btn-theme-toggle');
    if (toggle) {
      e.preventDefault();
      const currentDark = document.documentElement.classList.contains('dark');
      applyTheme(!currentDark);
    }
  });

  /* ── Scroll reveal ── */
  // Elements with class "reveal" fade up as they enter the viewport.
  // Gate: only animate when JS is on (html.js) and motion is not reduced.
  const prefersReduced = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (!prefersReduced && document.documentElement.classList.contains('js')) {
    const targets = document.querySelectorAll('.reveal');
    if ('IntersectionObserver' in window && targets.length) {
      const io = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('revealed');
            io.unobserve(entry.target);
          }
        });
      }, { threshold: 0.12 });
      targets.forEach((el) => io.observe(el));
    } else {
      targets.forEach((el) => el.classList.add('revealed'));
    }
  }

  /* ── Sticky nav shadow + active section highlight ── */
  const navbar = document.querySelector('.navbar');
  if (navbar) {
    const onScroll = () => {
      navbar.classList.toggle('scrolled', window.scrollY > 8);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  const sections = document.querySelectorAll('section[id]');
  const navLinks = Array.prototype.slice.call(
    document.querySelectorAll('.nav-link[href^="#"]')
  );
  if (sections.length && navLinks.length && 'IntersectionObserver' in window) {
    const spy = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const id = entry.target.getAttribute('id');
          navLinks.forEach((link) => {
            const href = link.getAttribute('href');
            link.classList.toggle('active', href === '#' + id);
          });
        }
      });
    }, { rootMargin: '-40% 0px -55% 0px' });
    sections.forEach((el) => spy.observe(el));
  }

  /* ── Accessibility: skip-to-content ── */
  const skipLink = document.getElementById('skip-to-content');
  if (skipLink) {
    skipLink.addEventListener('click', (e) => {
      e.preventDefault();
      const main = document.querySelector('main');
      if (main) {
        main.setAttribute('tabindex', '-1');
        main.focus({ preventScroll: false });
        main.scrollIntoView();
      }
    });
  }


  /* ── Button press feedback (safe: transform only) ── */
  document.addEventListener('mousedown', (e) => {
    const btn = e.target.closest('button, .btn-hero-primary, .btn-hero-secondary, .btn-nav-launch');
    if (btn && !btn.disabled) btn.classList.add('pressed');
  });
  document.addEventListener('mouseup', (e) => {
    const btn = e.target.closest('button, .btn-hero-primary, .btn-hero-secondary, .btn-nav-launch');
    if (btn) btn.classList.remove('pressed');
  });
})();
