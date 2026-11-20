import { Pipe, PipeTransform } from '@angular/core';
import { IsDenied, NetqueryConnection } from '@safing/portmaster-api';

@Pipe({
    name: "isBlocked",
    pure: true,
    standalone: false
})
export class IsBlockedConnectionPipe implements PipeTransform {
  transform(conn: NetqueryConnection): boolean {
    return IsDenied(conn?.verdict);
  }
}
