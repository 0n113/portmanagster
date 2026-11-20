import { ChangeDetectionStrategy, Component } from '@angular/core';

@Component({
    selector: 'app-side-dash',
    templateUrl: './side-dash.html',
    styleUrls: ['./side-dash.scss'],
    changeDetection: ChangeDetectionStrategy.OnPush,
    standalone: false
})
export class SideDashComponent { }
