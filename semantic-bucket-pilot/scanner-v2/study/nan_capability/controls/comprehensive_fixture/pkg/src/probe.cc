#include <nan.h>
#include <node.h>
#include <map>

using namespace v8;

struct SharedArea {
  char *pBuffer;
  int size;
};

class Widget : public Nan::ObjectWrap {
 public:
  static Nan::Persistent<v8::FunctionTemplate> constructor;
  std::map<int, SharedArea> areaMap;

  static NAN_MODULE_INIT(Init) {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(Widget::New);
    tpl->SetClassName(Nan::New("Widget").ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    Nan::SetPrototypeMethod(tpl, "readAreaLike", Widget::ReadAreaLike);
    Nan::SetPrototypeMethod(tpl, "uploadLike", Widget::UploadLike);
    Nan::SetPrototypeMethod(tpl, "guardedLike", Widget::GuardedLike);
    Nan::SetPrototypeMethod(tpl, "internalConstantLike", Widget::InternalConstantLike);
    Nan::SetPrototypeMethod(tpl, "copyGoodLike", Widget::CopyGoodLike);
    Nan::SetPrototypeMethod(tpl, "copyMismatchLike", Widget::CopyMismatchLike);
    Nan::SetPrototypeMethod(tpl, "copyUnresolvedLike", Widget::CopyUnresolvedLike);

    constructor.Reset(tpl);
    Nan::Set(target, Nan::New("Widget").ToLocalChecked(),
             Nan::GetFunction(tpl).ToLocalChecked());
  }

  static NAN_METHOD(New) {
    Widget *obj = new Widget();
    obj->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  }

  // POSITIVE 1: JS-argument-controlled length, product of two info[] reads, no bound check --
  // real shape confirmed on node-snap7's own S7Client::ReadArea.
  static NAN_METHOD(ReadAreaLike) {
    int amount = Nan::To<int32_t>(info[3]).FromJust();
    int byteCount = Nan::To<int32_t>(info[4]).FromJust();
    int size = amount * byteCount;
    char *bufferData = new char[size];
    v8::Local<v8::Object> ret = Nan::NewBuffer(
        bufferData, size, NULL, NULL).ToLocalChecked();
    info.GetReturnValue().Set(ret);
  }

  // POSITIVE 2: 2-arg NewBuffer(data, size) overload, single info[] source, no bound check.
  static NAN_METHOD(UploadLike) {
    int size = Nan::To<int32_t>(info[2]).FromJust();
    char *bufferData = new char[size];
    v8::Local<v8::Object> ret = Nan::NewBuffer(bufferData, size).ToLocalChecked();
    info.GetReturnValue().Set(ret);
  }

  // NEGATIVE (guarded): JS-argument-controlled, but an explicit upper-bound check dominates
  // the acquisition call -- must NOT be reported as unbounded.
  static NAN_METHOD(GuardedLike) {
    int size = Nan::To<int32_t>(info[1]).FromJust();
    if (size > 65536) {
      return Nan::ThrowRangeError("size too large");
    }
    char *bufferData = new char[size];
    v8::Local<v8::Object> ret = Nan::NewBuffer(bufferData, size).ToLocalChecked();
    info.GetReturnValue().Set(ret);
  }

  // NEGATIVE (not applicable): fixed literal size, never touches info[].
  static NAN_METHOD(InternalConstantLike) {
    Local<Value> result = Nan::NewBuffer(96).ToLocalChecked();
    info.GetReturnValue().Set(result);
  }

  // NEGATIVE (never registered): same unbounded shape as ReadAreaLike, but intentionally NOT
  // wired via SetPrototypeMethod anywhere in Init -- tests the registration gate.
  static NAN_METHOD(NotRegisteredLike) {
    int size = Nan::To<int32_t>(info[0]).FromJust();
    char *bufferData = new char[size];
    v8::Local<v8::Object> ret = Nan::NewBuffer(bufferData, size).ToLocalChecked();
    info.GetReturnValue().Set(ret);
  }

  // NEGATIVE for CopyBuffer (capacity matches by construction): the SAME identifier sizes the
  // local allocation and the copy length -- must NOT be promoted.
  static NAN_METHOD(CopyGoodLike) {
    int size = Nan::To<int32_t>(info[0]).FromJust();
    char *bufferData = new char[size];
    v8::Local<v8::Object> ret = Nan::CopyBuffer(bufferData, size).ToLocalChecked();
    info.GetReturnValue().Set(ret);
  }

  // POSITIVE for CopyBuffer: a real, local, FIXED allocation (128 bytes) whose capacity is
  // structurally independent of the JS-argument-controlled copy length -- a genuine
  // capacity/length mismatch, not merely "length is JS-controlled and source is unknown".
  static NAN_METHOD(CopyMismatchLike) {
    int copyLen = Nan::To<int32_t>(info[0]).FromJust();
    char *bufferData = new char[128];
    v8::Local<v8::Object> ret = Nan::CopyBuffer(bufferData, copyLen).ToLocalChecked();
    info.GetReturnValue().Set(ret);
  }

  // UNRESOLVED for CopyBuffer: the source pointer comes from an opaque map/struct field (no
  // local allocation site in this method at all) -- real shape matching node-snap7's own
  // server-side LockArea/area2buffer case. Must emit an unresolved verdict, never an inferred
  // OOB-read positive.
  static NAN_METHOD(CopyUnresolvedLike) {
    Widget *self = ObjectWrap::Unwrap<Widget>(info.Holder());
    int index = Nan::To<int32_t>(info[0]).FromJust();
    int size = Nan::To<int32_t>(info[1]).FromJust();
    v8::Local<v8::Object> ret = Nan::CopyBuffer(
        self->areaMap[index].pBuffer, size).ToLocalChecked();
    info.GetReturnValue().Set(ret);
  }
};

Nan::Persistent<v8::FunctionTemplate> Widget::constructor;

// Free-function registration idiom (Nan::SetMethod on the module `exports`/`target` object,
// distinct from Nan::SetPrototypeMethod's class-instance idiom above) -- checked for real, not
// assumed to share the same argument shape.
NAN_METHOD(TopLevelLike) {
  int size = Nan::To<int32_t>(info[0]).FromJust();
  char *bufferData = new char[size];
  v8::Local<v8::Object> ret = Nan::NewBuffer(bufferData, size).ToLocalChecked();
  info.GetReturnValue().Set(ret);
}

NAN_MODULE_INIT(InitAll) {
  Widget::Init(target);
  Nan::SetMethod(target, "topLevelLike", TopLevelLike);
}

NODE_MODULE(probe, InitAll)
