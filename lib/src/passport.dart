import 'dart:typed_data';
import 'package:readnfc/dmrtd.dart';
import 'package:readnfc/extensions.dart';
import 'package:logging/logging.dart';

import 'proto/iso7816/icc.dart';
import 'proto/iso7816/response_apdu.dart';
import 'proto/mrtd_api.dart';

class PassportError implements Exception {
  final String message;
  final StatusWord? code;
  PassportError(this.message, {this.code});
  @override
  String toString() => message;
}

enum _DF { None, MF, DF1 }

class Passport {
  static const aaChallengeLen = 8;

  final _log = Logger("passport");
  final MrtdApi _api;
  _DF _dfSelectd = _DF.None;

  Passport(final ComProvider provider) : _api = MrtdApi(provider);

  Future<void> startSession(final DBAKeys keys) async {
    _log.debug("Starting session");
    //await _selectDF1();
    await _exec(() => _api.initSessionViaBAC(keys));
    _log.debug("Session established");
  }

  Future<Uint8List> activeAuthenticate(final Uint8List challenge) async {
    return await _exec(() => _api.activeAuthenticate(challenge));
  }

  Future<EfCardAccess> readEfCardAccess() async {
    _log.debug("Reading EF.CardAccess");

    await _api.selectEFFile(Uint8List.fromList([0x01, 0x1C]));
    return EfCardAccess.fromBytes(
        await _exec(() => _api.readFileBySFI(EfCardAccess.SFI)));
  }

  Future<EfCardSecurity> readEfCardSecurity() async {
    _log.debug("Reading EF.CardSecurity");
    // await _selectMF();
    return EfCardSecurity.fromBytes(
        await _exec(() => _api.readFileBySFI(EfCardSecurity.SFI)));
  }

  Future<EfCOM> readEfCOM() async {
    _log.debug("Reading EF.COM");
    await _selectDF1();
    return EfCOM.fromBytes(await _exec(() => _api.readFileBySFI(EfCOM.SFI)));
  }

  Future<EfDG1> readEfDG1() async {
    await _selectDF1();
    _log.debug("Reading EF.DG1");
    return EfDG1.fromBytes(await _exec(() => _api.readFileBySFI(EfDG1.SFI)));
  }

  Future<EfDG2> readEfDG2() async {
    _log.debug("Reading EF.DG2");
    await _selectDF1();
    return EfDG2.fromBytes(await _exec(() => _api.readFileBySFI(EfDG2.SFI)));
  }

  Future<EfDG3> readEfDG3() async {
    _log.debug("Reading EF.DG3");
    await _selectDF1();
    return EfDG3.fromBytes(await _exec(() => _api.readFileBySFI(EfDG3.SFI)));
  }

  Future<EfDG4> readEfDG4() async {
    _log.debug("Reading EF.DG4");
    await _selectDF1();
    return EfDG4.fromBytes(await _exec(() => _api.readFileBySFI(EfDG4.SFI)));
  }

  Future<EfDG5> readEfDG5() async {
    _log.debug("Reading EF.DG5");
    await _selectDF1();
    return EfDG5.fromBytes(await _exec(() => _api.readFileBySFI(EfDG5.SFI)));
  }

  Future<EfDG6> readEfDG6() async {
    _log.debug("Reading EF.DG6");
    await _selectDF1();
    return EfDG6.fromBytes(await _exec(() => _api.readFileBySFI(EfDG6.SFI)));
  }

  Future<EfDG7> readEfDG7() async {
    _log.debug("Reading EF.DG7");
    await _selectDF1();
    return EfDG7.fromBytes(await _exec(() => _api.readFileBySFI(EfDG7.SFI)));
  }

  Future<EfDG8> readEfDG8() async {
    _log.debug("Reading EF.DG8");
    await _selectDF1();
    return EfDG8.fromBytes(await _exec(() => _api.readFileBySFI(EfDG8.SFI)));
  }

  Future<EfDG9> readEfDG9() async {
    _log.debug("Reading EF.DG9");
    await _selectDF1();
    return EfDG9.fromBytes(await _exec(() => _api.readFileBySFI(EfDG9.SFI)));
  }

  Future<EfDG10> readEfDG10() async {
    _log.debug("Reading EF.DG10");
    await _selectDF1();
    return EfDG10.fromBytes(await _exec(() => _api.readFileBySFI(EfDG10.SFI)));
  }

  Future<EfDG11> readEfDG11() async {
    _log.debug("Reading EF.DG11");
    await _selectDF1();
    return EfDG11.fromBytes(await _exec(() => _api.readFileBySFI(EfDG11.SFI)));
  }

  Future<EfDG12> readEfDG12() async {
    _log.debug("Reading EF.DG12");
    await _selectDF1();
    return EfDG12.fromBytes(await _exec(() => _api.readFileBySFI(EfDG12.SFI)));
  }

  Future<EfDG13> readEfDG13() async {
    _log.debug("Reading EF.DG13");
    await _selectDF1();
    return EfDG13.fromBytes(await _exec(() => _api.readFileBySFI(EfDG13.SFI)));
  }

  Future<EfDG14> readEfDG14() async {
    await _selectDF1();
    _log.debug("Reading EF.DG14");
    return EfDG14.fromBytes(await _exec(() => _api.readFileBySFI(EfDG14.SFI)));
  }

  Future<EfDG15> readEfDG15() async {
    _log.debug("Reading EF.DG15");
    await _selectDF1();
    return EfDG15.fromBytes(await _exec(() => _api.readFileBySFI(EfDG15.SFI)));
  }

  Future<EfDG16> readEfDG16() async {
    _log.debug("Reading EF.DG16");
    await _selectDF1();
    return EfDG16.fromBytes(await _exec(() => _api.readFileBySFI(EfDG16.SFI)));
  }

  Future<EfSOD> readEfSOD() async {
    _log.debug("Reading EF.SOD");
    await _selectDF1();
    return EfSOD.fromBytes(await _exec(() => _api.readFileBySFI(EfSOD.SFI)));
  }

  Future<void> _selectMF() async {
    if (_dfSelectd != _DF.MF) {
      _log.debug("Selecting MF");
      await _exec(() => _api.selectMasterFile());
      _dfSelectd = _DF.MF;
    }
  }

  Future<void> _selectDF1() async {
    if (_dfSelectd != _DF.DF1) {
      _log.debug("Selecting DF1");
      await _exec(() => _api.selectEMrtdApplication());
      _dfSelectd = _DF.DF1;
    }
  }

  Future<T> _exec<T>(Function f) async {
    try {
      return await f();
    } on ICCError catch (e) {
      var msg = e.sw.description();
      if (e.sw.sw1 == 0x63 && e.sw.sw2 == 0xcf) {
        msg = StatusWord.securityStatusNotSatisfied.description();
      }
      throw PassportError(msg, code: e.sw);
    } on MrtdApiError catch (e) {
      throw PassportError(e.message, code: e.code);
    }
  }
}
