import { HttpClient } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, DestroyRef, Inject, OnInit, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { PORTMASTER_HTTP_API_ENDPOINT } from '@safing/portmaster-api';
import { Observable, catchError, of, startWith, switchMap, timer } from 'rxjs';

/** ManagedStatus is the state of the management client (managed/status). */
export interface ManagedStatus {
  enrolled: boolean;
  server?: string;
  computerId?: string;
  group?: string;
  appliedVersion?: number;
  lastPull?: string;
  lastSuccess?: string;
  lastError?: string;
  lastReport?: string;
  lastReportError?: string;
  overridden?: string[];
  refused?: string[];
}

/**
 * Shows whether this computer is managed by a portmanagster server, and
 * the state of its policy. Shows nothing if it is not managed.
 */
@Component({
  selector: 'app-managed-panel',
  templateUrl: './managed-panel.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  standalone: false,
})
export class ManagedPanelComponent implements OnInit {
  private readonly destroyRef = inject(DestroyRef);

  /** The current status, null until loaded or if not available. */
  status$: Observable<ManagedStatus | null> = of(null);

  constructor(
    private http: HttpClient,
    @Inject(PORTMASTER_HTTP_API_ENDPOINT) private httpAPI: string,
  ) { }

  ngOnInit(): void {
    this.status$ = timer(0, 30000).pipe(
      switchMap(() =>
        this.http.get<ManagedStatus>(`${this.httpAPI}/v1/managed/status`).pipe(
          // An older core without the management client has no endpoint.
          catchError(() => of(null)),
        ),
      ),
      startWith(null),
      takeUntilDestroyed(this.destroyRef),
    );
  }
}
