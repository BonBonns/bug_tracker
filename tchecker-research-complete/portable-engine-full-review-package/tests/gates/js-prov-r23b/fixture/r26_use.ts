import { r26ChainTerminal as r26SingleHop } from './r26_chain_mid';
import { r26ChainTerminal as r26Transitive } from './r26_chain_top';
import { r26MissingAbsent as r26Missing } from './r26_missing_reexport';
import { r26CycleSpin as r26Spin } from './r26_cycle_a';
import { r26MutualViaB as r26Mutual } from './r26_mutual_b';
import { r26StarMember as r26Star } from './r26_star_reexport';
declare function use(x: any): any;
use(r26SingleHop(1)); use(r26Transitive(2)); use(r26Missing(3));
use(r26Spin(4)); use(r26Mutual(5)); use(r26Star(6));
