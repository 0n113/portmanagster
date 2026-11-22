# UI changes in portmasterpro

The UI is the Angular app in `desktop/angular` (Angular 20, Node 22), built into the Tauri
desktop app in `desktop/tauri`.

## Removed

- The SPN page, map entry and quick settings, "Pause SPN", SPN identities, the SPN column and
  filter in the connection list, SPN parts of the connection details and help texts.
- Login, account details, pricing, feature upsell and "Portmaster Plus/Pro" copy.
- The SPN and account services in `@safing/portmaster-api` and the `RequiresFeatureID`
  annotation of settings.
- SPN entries in the tray menu (`desktop/tauri`).

## Changed

- Network History and Bandwidth Visibility are always shown; no subscription check.
- The world map lives in `shared/map-renderer` and shows local connection data.
- The UI connects only to the local API.
- Several security fixes: HTML injection through app names, the app authorization prompt,
  API trust for the app's own webview only.
- Angular 16 → 20, with ng-zorro, ngx-markdown and Font Awesome updated to match.

## Kept on purpose

Neutral fields of the local connection data (`exit_node`, `tunneled`) and the `SPN` field of the
pause state: the core still sends them, always empty or `false`.
