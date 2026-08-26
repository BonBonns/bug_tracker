// NOSQLI: AJV route-schema-gate detection fixtures. Based directly on the real structural pattern
// confirmed in RocketChat's server/api/v1/*.ts: API.v1.get/post(name, { ..., body: X, query: Y,
// ... }, { async function action() { ... } }) -- a sink inside such an action() function may be
// gated by a schema this tool cannot always resolve (the schema is often defined in a separate
// package). The correct behavior is UNKNOWN when the gate is detected but not resolvable -- never
// silently PRESERVES (which is what led to four manually-chased false leads this session).
const API = { v1: { get: (name, opts, handlers) => {}, post: (name, opts, handlers) => {} } };
const Meteor = { methods: (obj) => obj };

// --- real shape: a POST route with a body: schema gate, sink inside action() ---
API.v1.post(
  'integrations.remove',
  {
    authRequired: true,
    body: isIntegrationsRemoveProps,
  },
  {
    async action() {
      const { bodyParams } = this;
      return Integrations.findOne({ _id: bodyParams.integrationId });
    },
  },
);

// --- real shape: a GET route with a query: schema gate ---
API.v1.get(
  'emoji-custom.list',
  {
    authRequired: true,
    query: isEmojiCustomList,
  },
  {
    async action() {
      const { _id } = this.queryParams;
      return EmojiCustom.find({ _id });
    },
  },
);

// --- no schema gate at all: genuinely unguarded, should remain PRESERVES ---
API.v1.post(
  'noSchemaGate',
  {
    authRequired: true,
  },
  {
    async action() {
      const { bodyParams } = this;
      return Users.findOne({ username: bodyParams.username });
    },
  },
);

// --- NOT inside an API route at all -- a plain Meteor method, unaffected by this mechanism,
// must not be misclassified as gated just because a body:/query: identifier exists ELSEWHERE ---
async function plainMeteorMethod(userInput) {
  return Users.findOne({ username: userInput });
}
Meteor.methods({ plainMeteorMethod });
