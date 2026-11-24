import { ChangeDetectionStrategy, ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { SFNG_DIALOG_REF, SfngDialogRef } from '@safing/ui';
import {
  AppearanceService,
  AppearanceSettings,
  FontOption,
  RadiusOption,
  TextSizeOption,
  ThemeName,
  defaultAppearance,
} from 'src/app/services/appearance.service';
import { ActionIndicatorService } from 'src/app/shared/action-indicator';

interface ThemeChoice {
  id: ThemeName;
  name: string;
  description: string;
  // Colors of the small preview: background, card, accent.
  preview: [string, string, string];
}

interface Choice<T> {
  id: T;
  name: string;
}

@Component({
  templateUrl: './appearance-dialog.html',
  styleUrls: ['./appearance-dialog.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush,
  standalone: false,
})
export class AppearanceDialogComponent implements OnInit, OnDestroy {
  private readonly dialogRef: SfngDialogRef<AppearanceDialogComponent> = inject(SFNG_DIALOG_REF);
  private readonly appearance = inject(AppearanceService);
  private readonly uai = inject(ActionIndicatorService);
  private readonly cdr = inject(ChangeDetectorRef);

  readonly themes: ThemeChoice[] = [
    { id: 'macos', name: 'macOS Dark', description: 'System grays, as in WhiteSur', preview: ['#1a1a1d', '#252528', '#0a84ff'] },
    { id: 'graphite', name: 'Graphite', description: 'Lighter, neutral gray', preview: ['#28282b', '#343438', '#0a84ff'] },
    { id: 'midnight', name: 'Midnight', description: 'Black, for OLED screens', preview: ['#000000', '#161618', '#0a84ff'] },
    { id: 'classic', name: 'Classic', description: 'The original Portmaster', preview: ['#121213', '#222222', '#4e97fa'] },
  ];

  /** The macOS accent colors. */
  readonly accents: Choice<string>[] = [
    { id: '#0a84ff', name: 'Blue' },
    { id: '#bf5af2', name: 'Purple' },
    { id: '#ff375f', name: 'Pink' },
    { id: '#ff453a', name: 'Red' },
    { id: '#ff9f0a', name: 'Orange' },
    { id: '#ffd60a', name: 'Yellow' },
    { id: '#30d158', name: 'Green' },
    { id: '#40c8e0', name: 'Teal' },
    { id: '#8e8e93', name: 'Graphite' },
  ];

  readonly radii: Choice<RadiusOption>[] = [
    { id: 'theme', name: 'Theme' },
    { id: 'square', name: 'Square' },
    { id: 'rounded', name: 'Rounded' },
    { id: 'round', name: 'Round' },
  ];

  readonly fonts: Choice<FontOption>[] = [
    { id: 'theme', name: 'Theme' },
    { id: 'system', name: 'System' },
    { id: 'roboto', name: 'Roboto' },
    { id: 'mono', name: 'Monospace' },
  ];

  readonly textSizes: Choice<TextSizeOption>[] = [
    { id: 'small', name: 'Small' },
    { id: 'normal', name: 'Normal' },
    { id: 'large', name: 'Large' },
  ];

  /** The settings when the dialog opened, restored on cancel. */
  private saved: AppearanceSettings = defaultAppearance;

  /** Whether the shown settings were saved. */
  private done = false;

  /** The settings shown in the dialog, previewed live. */
  value: AppearanceSettings = defaultAppearance;

  ngOnInit(): void {
    this.saved = { ...this.appearance.settings };
    this.value = { ...this.saved };
  }

  /** The color shown in the color picker. */
  get customAccent(): string {
    return this.value.accent || '#0a84ff';
  }

  get isCustomAccent(): boolean {
    return !!this.value.accent && !this.accents.some(a => a.id === this.value.accent);
  }

  update<K extends keyof AppearanceSettings>(key: K, val: AppearanceSettings[K]): void {
    this.value = { ...this.value, [key]: val };
    this.appearance.preview(this.value);
    this.cdr.markForCheck();
  }

  reset(): void {
    this.value = { ...defaultAppearance };
    this.appearance.preview(this.value);
    this.cdr.markForCheck();
  }

  cancel(): void {
    this.appearance.preview(this.saved);
    this.dialogRef.close();
  }

  ngOnDestroy(): void {
    // Closed without saving (cancel, backdrop, escape): undo the preview.
    if (!this.done) {
      this.appearance.preview(this.saved);
    }
  }

  save(): void {
    this.appearance.save(this.value).subscribe({
      next: () => {
        this.done = true;
        this.uai.success('Appearance saved');
        this.dialogRef.close();
      },
      error: err => this.uai.error('Failed to save the appearance', this.uai.getErrorMessgae(err)),
    });
  }
}
