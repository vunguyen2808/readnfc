import 'dart:math';
import 'dart:typed_data';
import 'package:readnfc/extensions.dart';
import 'package:readnfc/src/com/com_provider.dart';
import 'package:readnfc/src/lds/tlv.dart';
import 'package:readnfc/src/utils.dart';
import 'package:logging/logging.dart';

import 'command_apdu.dart';
import 'iso7816.dart';
import 'response_apdu.dart';
import 'sm.dart';

class ICCError implements Exception {
  final String message;
  final StatusWord sw;
  final Uint8List? data;
  ICCError(this.message, this.sw, this.data);
  @override
  String toString() => 'ICC Error: $message $sw';
}

class ICC {
  final ComProvider _com;
  final _log = Logger("icc");
  SecureMessaging? sm;

  ICC(this._com);

  Future<void> connect() async {
    return await _com.connect();
  }

  Future<void> disconnect() async {
    return await _com.disconnect();
  }

  bool isConnected() {
    return _com.isConnected();
  }

  Future<Uint8List> externalAuthenticate(
      {required Uint8List data,
      required int ne,
      int cla = ISO7816_CLA.NO_SM}) async {
    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.EXTERNAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data: data,
        ne: ne));
    if (rapdu.status != StatusWord.success) {
      throw ICCError("External authenticate failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  Future<Uint8List> internalAuthenticate(
      {required Uint8List data,
      int p1 = 0x00,
      int p2 = 0x00,
      required int ne,
      int cla = ISO7816_CLA.NO_SM}) async {
    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.INTERNAL_AUTHENTICATE,
        p1: p1,
        p2: p2,
        data: data,
        ne: ne));
    if (rapdu.status != StatusWord.success) {
      throw ICCError("Internal authenticate failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  Future<Uint8List> getChallenge(
      {required int challengeLength, int cla = ISO7816_CLA.NO_SM}) async {
    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.GET_CHALLENGE,
        p1: 0x00,
        p2: 0x00,
        ne: challengeLength));
    if (rapdu.status != StatusWord.success) {
      throw ICCError("Get challenge failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  Future<ResponseAPDU> readBinary(
      {required int offset,
      required int ne,
      int cla = ISO7816_CLA.NO_SM}) async {
    if (offset > 32766) {
      throw ArgumentError.value(
          offset, null, "Max read binary offset can be 32 767 bytes");
    }

    Uint8List rawOffset = Utils.intToBin(offset, minLen: 2);
    final p1 = rawOffset[0];
    final p2 = rawOffset[1];

    return await _readBinary(CommandAPDU(
        cla: cla, ins: ISO7816_INS.READ_BINARY, p1: p1, p2: p2, ne: ne));
  }

  Future<ResponseAPDU> readBinaryBySFI(
      {required int sfi,
      required int offset,
      required int ne,
      int cla = ISO7816_CLA.NO_SM}) async {
    if (offset > 255) {
      throw ArgumentError.value(
          offset, null, "readBinaryBySFI: Max offset can be 256 bytes");
    }
    if ((sfi & 0x80) == 0) {
      // bit 8 must be set
      throw ArgumentError.value(
          offset, null, "readBinaryBySFI: Invalid SFI identifier");
    }

    return await _readBinary(CommandAPDU(
        cla: cla, ins: ISO7816_INS.READ_BINARY, p1: sfi, p2: offset, ne: ne));
  }

  Future<ResponseAPDU> readBinaryExt(
      {required int offset,
      required int ne,
      int cla = ISO7816_CLA.NO_SM}) async {
    final enNeLen = TLV.encodeLength(ne).length;
    final addBytes = 1 /*byte = tag*/ + enNeLen;
    ne = ne <= 256 ? min(256, ne + addBytes) : ne + addBytes;

    final data = TLV.encodeIntValue(0x54, offset);
    final rapdu = await _readBinary(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.READ_BINARY_EXT,
        p1: 0x00,
        p2: 0x00,
        data: data,
        ne: ne));

    final rtlv = TLV.fromBytes(rapdu.data!);
    if (rtlv.tag != 0x53) {
      throw ICCError(
          "readBinaryExt failed. Received invalid BER-TLV encoded data with tag=0x${rtlv.tag.hex()}, expected tag=0x53",
          rapdu.status,
          rapdu.data);
    }
    return ResponseAPDU(rapdu.status, rtlv.value);
  }

  Future<Uint8List?> selectFile(
      {required int p1,
      required int p2,
      int cla = ISO7816_CLA.NO_SM,
      Uint8List? data,
      int ne = 0}) async {
    CommandAPDU commandAPDU = CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.SELECT_FILE,
        p1: p1,
        p2: p2,
        data: data,
        ne: ne);
    _log.info("CommandAPDU: ${commandAPDU.toBytes().hex()}");
    final rapdu = await _transceive(commandAPDU);
    _log.info("ResponseAPDU: ${rapdu.toBytes().hex()}");
    if (rapdu.status != StatusWord.success) {
      throw ICCError("Select File failed", rapdu.status, rapdu.data);
    }
    return rapdu.data;
  }

  Future<Uint8List?> selectFileById(
      {required Uint8List fileId,
      int p2 = 0,
      int cla = ISO7816_CLA.NO_SM,
      int ne = 0}) async {
    return await selectFile(
        cla: cla, p1: ISO97816_SelectFileP1.byID, p2: p2, data: fileId, ne: ne);
  }

  Future<Uint8List?> selectChildDF(
      {required Uint8List childDF,
      int p2 = 0,
      int cla = ISO7816_CLA.NO_SM,
      int ne = 0}) async {
    return await selectFile(
        cla: cla,
        p1: ISO97816_SelectFileP1.byChildDFID,
        p2: p2,
        data: childDF,
        ne: ne);
  }

  Future<Uint8List?> selectEF(
      {required Uint8List efId,
      int p2 = 0,
      int cla = ISO7816_CLA.NO_SM,
      int ne = 0}) async {
    return await selectFile(
        cla: cla, p1: ISO97816_SelectFileP1.byEFID, p2: p2, data: efId, ne: ne);
  }

  Future<Uint8List?> selectParentDF(
      {int p2 = 0, int cla = ISO7816_CLA.NO_SM, int ne = 0}) async {
    return await selectFile(
        cla: cla, p1: ISO97816_SelectFileP1.parentDF, p2: p2, ne: ne);
  }

  Future<Uint8List?> selectFileByDFName(
      {required Uint8List dfName,
      int p2 = 0,
      int cla = ISO7816_CLA.NO_SM,
      int ne = 0}) async {
    return await selectFile(
        cla: cla,
        p1: ISO97816_SelectFileP1.byDFName,
        p2: p2,
        data: dfName,
        ne: ne);
  }

  Future<Uint8List?> selectFileByPath(
      {required Uint8List path,
      required bool fromMF,
      int p2 = 0,
      int cla = ISO7816_CLA.NO_SM,
      int ne = 0}) async {
    final p1 = fromMF
        ? ISO97816_SelectFileP1.byPathFromMF
        : ISO97816_SelectFileP1.byPath;
    return await selectFile(cla: cla, p1: p1, p2: p2, data: path, ne: ne);
  }

  Future<ResponseAPDU> _readBinary(final CommandAPDU cmd) async {
    assert(cmd.ins == ISO7816_INS.READ_BINARY_EXT ||
        cmd.ins == ISO7816_INS.READ_BINARY);

    final rapdu = await _transceive(cmd);
    if ((rapdu.data?.isEmpty ?? true) && rapdu.status.isError()) {
      throw ICCError("Read binary failed", rapdu.status, rapdu.data);
    }
    return rapdu;
  }

  Future<ResponseAPDU> _transceive(final CommandAPDU cmd) async {
    _log.debug("Transceiving to ICC: $cmd");
    final rawCmd = _wrap(cmd).toBytes();

    _log.debug(
        "Sending ${rawCmd.length} byte(s) to ICC: data='${rawCmd.hex()}'");
    Uint8List rawResp = await _com.transceive(rawCmd);
    _log.debug("Received ${rawResp.length} byte(s) from ICC");
    _log.sdDebug(" data='${rawResp.hex()}'");

    final rapdu = _unwrap(ResponseAPDU.fromBytes(rawResp));
    _log.debug(
        "Received response from ICC: ${rapdu.status} data_len=${rapdu.data?.length ?? 0}");
    _log.sdDebug(" data=${rapdu.data?.hex()}");
    return rapdu;
  }

  CommandAPDU _wrap(final CommandAPDU cmd) {
    if (sm != null) {
      return sm!.protect(cmd);
    }
    return cmd;
  }

  ResponseAPDU _unwrap(final ResponseAPDU resp) {
    if (sm != null) {
      return sm!.unprotect(resp);
    }
    return resp;
  }
}
