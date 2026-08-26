import { realFn } from './mid';
import { realFn as viaTop } from './top';
import { missing } from './mid';
import { fromCyc2 } from './cyc2';
declare function use(x:any):any;
use(realFn(1)); use(viaTop(2)); use(missing(3)); use(fromCyc2(4));
