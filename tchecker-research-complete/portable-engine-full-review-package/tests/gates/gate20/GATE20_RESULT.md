# Gate 20 — indexed/container state provenance

## Goal
Extend the receiver-sensitive state model from named properties to indexed/container state (`obj[key]`, `arr[i]`) without collapsing a dynamic key into global container taint.

No security sources/sinks were added.

## Frontend representation
The TS→legacy CSV adapter now lowers `ElementAccessExpression` to the existing `AST_DIM` form:

- child 0 = container expression
- child 1 = index/key expression

The real legacy engine accepts and analyzes the generated graph end-to-end.

## State identity
Exact members use `receiver identity + normalized key/index`:

- `box["fixed"]` → `PARAMOBJ:fn.box[S:fixed]`
- `arr[0]` → `PARAMOBJ:fn.arr[N:0]`

A dynamic key is *not* treated as every member. It is represented as a possible write/read over the receiver. Reads of one exact slot only incorporate dynamic writes that occur after the latest exact write to that slot. Thus a later exact overwrite kills earlier uncertainty for that exact member.

## Measured real-engine result
With the existing COMPLETE + MAY state-summary bridges enabled:

```text
objectStaticExact(box, source)       hard=[1]
objectStaticDifferent(box, source)   hard=[]
objectStaticOverwrite(box, source)   hard=[]

objectDynamicWrite(box,key,source)   hard=[]  MAY=AMBIGUOUS [2]
objectDynamicRead(box,key,source)    hard=[]  MAY=AMBIGUOUS [2]

arrayStaticExact(arr,source)         hard=[1]
arrayStaticDifferent(arr,source)     hard=[]
arrayDynamicWrite(arr,i,source)      hard=[]  MAY=AMBIGUOUS [2]
arrayDynamicRead(arr,i,source)       hard=[]  MAY=AMBIGUOUS [2]

differentReceiver(a,b,key,source)    hard=[]
```

The important integration detail is that uncertain functions emit **both**:

- a `COMPLETE` hard summary containing only guaranteed parameter positions (empty in these four cases), and
- an `AMBIGUOUS` MAY summary containing possible positions.

That prevents the legacy `AST_DIM` analysis from simultaneously leaving a coarse hard source in place.

## Why the dual summary matters
Gate-off results expose the old container-level coarseness:

```text
objectStaticDifferent   [0,1]
objectStaticOverwrite   [0,1]
objectDynamicRead       [0,1,2]
arrayStaticDifferent    [0,1]
arrayDynamicRead        [0,1,2]
differentReceiver       [0]
```

So the legacy engine conflates container identity, key/index, and stored value. The frontend state abstraction corrects this without global property/index taint.

## Automated result
`gate20_test.py`: **GATE20=14/14**.

The full detector subset required for the analysis rebuilt successfully (two pre-existing deprecation warnings, zero errors), and the generated graph was executed by the real `PHPCGFactory`/return-summary machinery.

## Boundary
This gate covers element/index access and dynamic keys. It intentionally does **not** claim destructuring support yet. The next gate should lower and model destructuring (`const {fixed}=box`, `const [first]=arr`) as reads of exact members, then test rest/spread and computed destructuring separately because those can introduce ambiguity.
