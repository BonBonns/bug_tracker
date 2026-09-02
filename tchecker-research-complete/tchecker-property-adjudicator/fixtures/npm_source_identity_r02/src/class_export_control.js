// Export-surface capability: `module.exports = SomeClass` -- the constructor itself is NOT the
// public API surface (CLASS_CONSTRUCTOR_NOT_PUBLIC_API, abstained), but the class's OTHER
// instance methods are real, resolved export-surface members.
class Widget {
  constructor(owner) {
    this.owner = owner;
  }

  process(input) {
    return input;
  }

  describe() {
    return this.owner;
  }
}

module.exports = Widget;
