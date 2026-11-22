import { enableProdMode, importProvidersFrom } from '@angular/core';
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';

import { AppModule } from './app/app.module';
import { environment } from './environments/environment';
import { INTEGRATION_SERVICE, integrationServiceFactory } from './app/integration';
import { bootstrapApplication } from '@angular/platform-browser';
import { PromptEntryPointComponent } from './app/prompt-entrypoint/prompt-entrypoint';
import { provideHttpClient } from '@angular/common/http';
import { PortmasterAPIModule } from '@safing/portmaster-api';
import { NotificationsService } from './app/services';
import { TauriIntegrationService } from './app/integration/taur-app';

if (environment.production) {
  enableProdMode();
}

if (typeof (CSS as any)['registerProperty'] === 'function') {
  (CSS as any).registerProperty({
    name: '--lock-color',
    syntax: '*',
    inherits: true,
    initialValue: '10, 10, 10'
  })
}

function handleExternalResources(e: Event) {
  // Links inside the app may come from untrusted text (notifications,
  // imported profiles, news), so every click on an "<a />" passes here:
  // links to the app itself load normally, all others open in the system
  // browser and never in the app window.

  // get click target
  let target: HTMLElement | null = e.target as HTMLElement;
    
  // traverse until we reach element "<a />"
  while (target && target.tagName !== "A") {
    target = target.parentElement;
  }

  if (target) {
    const href = target.getAttribute("href");
    if (href?.startsWith("blob")) {
      return
    }

    if (!href) {
      return
    }

    // Only links to our own origin may load inside the app. A link is
    // compared by its parsed origin: a substring check on the host name
    // would treat "https://127.0.0.1.example.com/" as internal and load a
    // foreign page into the privileged app window.
    let url: URL;
    try {
      url = new URL(href, location.href);
    } catch {
      e.preventDefault();
      return
    }

    if (url.origin === location.origin) {
      return
    }

    e.preventDefault();

    // Hand only web and mail links to the system.
    if (["http:", "https:", "mailto:"].includes(url.protocol)) {
      integrationServiceFactory().openExternal(url.href);
    }
  }
}

if (document.addEventListener) {
  document.addEventListener("click", handleExternalResources);
}

// load the font file but make sure to use the slimfix version
// windows.
{
  // we cannot use document.writeXX here as it's not allowed to
  // write to Document from an async loaded script.

  const linkTag = document.createElement("link");
  linkTag.rel = "stylesheet";
  linkTag.href = "/assets/fonts/roboto.css";
  if (navigator.platform.startsWith("Win")) {
    linkTag.href = "/assets/fonts/roboto-slimfix.css"
  }

  document.head.appendChild(linkTag);
}


if (location.pathname !== "/prompt") {
  // bootstrap our normal application
  platformBrowserDynamic().bootstrapModule(AppModule)
    .catch(err => console.error(err));

} else {
  // bootstrap the prompt interface
  console.log("[INFO] Bootstrapping prompt entry point.");
  bootstrapApplication(PromptEntryPointComponent, {
    providers: [
      provideHttpClient(),
      importProvidersFrom(PortmasterAPIModule.forRoot({
        websocketAPI: "ws://localhost:817/api/database/v1",
        httpAPI: "http://localhost:817/api"
      })),
      NotificationsService,
      {
        provide: INTEGRATION_SERVICE,
        useClass: TauriIntegrationService
      }
    ],
  })
}

