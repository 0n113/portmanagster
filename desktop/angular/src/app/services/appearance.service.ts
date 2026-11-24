import { Injectable, inject } from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { BehaviorSubject, Observable } from 'rxjs';
import { UIStateService } from './ui-state.service';

/** The themes of src/theme/_appearance.scss. */
export type ThemeName = 'macos' | 'classic' | 'midnight' | 'graphite';
/** "theme" uses the value of the theme. */
export type RadiusOption = 'theme' | 'square' | 'rounded' | 'round';
export type FontOption = 'theme' | 'system' | 'roboto' | 'mono';
export type TextSizeOption = 'small' | 'normal' | 'large';

export interface AppearanceSettings {
  theme: ThemeName;
  /** Accent color as #rrggbb, or null for the color of the theme. */
  accent: string | null;
  radius: RadiusOption;
  font: FontOption;
  textSize: TextSizeOption;
  reduceMotion: boolean;
}

export const defaultAppearance: AppearanceSettings = {
  theme: 'macos',
  accent: null,
  radius: 'theme',
  font: 'theme',
  textSize: 'normal',
  reduceMotion: false,
};

const themes: ThemeName[] = ['macos', 'classic', 'midnight', 'graphite'];
const radii: RadiusOption[] = ['theme', 'square', 'rounded', 'round'];
const fonts: FontOption[] = ['theme', 'system', 'roboto', 'mono'];
const textSizes: TextSizeOption[] = ['small', 'normal', 'large'];

/** Key of the copy in localStorage, applied before the core answers. */
const storageKey = 'portmaster.appearance';

/**
 * Applies and stores the appearance settings. They are kept in the UI state
 * of the core, so they survive a reinstall of the app, and in localStorage,
 * so the app starts in the right look without waiting for the core.
 */
@Injectable({ providedIn: 'root' })
export class AppearanceService {
  private readonly document = inject(DOCUMENT);
  private readonly uiState = inject(UIStateService);

  private readonly current = new BehaviorSubject<AppearanceSettings>(defaultAppearance);

  /** The active appearance settings. */
  readonly settings$: Observable<AppearanceSettings> = this.current.asObservable();

  get settings(): AppearanceSettings {
    return this.current.value;
  }

  /** Applies the stored settings, first the local copy, then the core's. */
  init(): void {
    this.apply(this.readLocal());

    this.uiState.uiState().subscribe({
      next: state => {
        if (state.appearance) {
          const settings = sanitize(state.appearance);
          this.apply(settings);
          this.writeLocal(settings);
        }
      },
      error: () => { /* keep the local copy */ },
    });
  }

  /** Applies settings right away, without saving them. */
  preview(settings: AppearanceSettings): void {
    this.apply(sanitize(settings));
  }

  /** Applies and saves settings. */
  save(settings: AppearanceSettings): Observable<void> {
    const clean = sanitize(settings);
    this.apply(clean);
    this.writeLocal(clean);
    return this.uiState.set('appearance', clean);
  }

  private apply(settings: AppearanceSettings): void {
    const root = this.document.documentElement;
    setData(root, 'theme', settings.theme === 'macos' ? null : settings.theme);
    setData(root, 'radius', settings.radius === 'theme' ? null : settings.radius);
    setData(root, 'font', settings.font === 'theme' ? null : settings.font);
    setData(root, 'textSize', settings.textSize === 'normal' ? null : settings.textSize);
    setData(root, 'reduceMotion', settings.reduceMotion ? 'true' : null);

    const accent = settings.accent ? hexToTriple(settings.accent) : null;
    if (accent) {
      root.style.setProperty('--pm-accent', accent);
    } else {
      root.style.removeProperty('--pm-accent');
    }

    this.current.next(settings);
  }

  private readLocal(): AppearanceSettings {
    try {
      const raw = localStorage.getItem(storageKey);
      return raw ? sanitize(JSON.parse(raw)) : defaultAppearance;
    } catch {
      return defaultAppearance;
    }
  }

  private writeLocal(settings: AppearanceSettings): void {
    try {
      localStorage.setItem(storageKey, JSON.stringify(settings));
    } catch {
      // Storage may be unavailable, the core keeps the settings.
    }
  }
}

function setData(el: HTMLElement, key: string, value: string | null): void {
  if (value === null) {
    delete el.dataset[key];
  } else {
    el.dataset[key] = value;
  }
}

/** Converts #rrggbb to "r g b", or null if invalid. */
export function hexToTriple(hex: string): string | null {
  const match = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  if (!match) {
    return null;
  }
  return match.slice(1).map(part => parseInt(part, 16)).join(' ');
}

/** Returns valid settings, with defaults for unknown or missing values. */
export function sanitize(value: Partial<AppearanceSettings> | null | undefined): AppearanceSettings {
  const v = value || {};
  return {
    theme: themes.includes(v.theme as ThemeName) ? v.theme as ThemeName : defaultAppearance.theme,
    accent: typeof v.accent === 'string' && hexToTriple(v.accent) ? v.accent.toLowerCase() : null,
    radius: radii.includes(v.radius as RadiusOption) ? v.radius as RadiusOption : defaultAppearance.radius,
    font: fonts.includes(v.font as FontOption) ? v.font as FontOption : defaultAppearance.font,
    textSize: textSizes.includes(v.textSize as TextSizeOption) ? v.textSize as TextSizeOption : defaultAppearance.textSize,
    reduceMotion: v.reduceMotion === true,
  };
}
