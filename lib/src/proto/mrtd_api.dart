import 'dart:typed_data';

import 'bac.dart';
import 'dba_keys.dart';
import 'iso7816/iso7816.dart';
import 'iso7816/icc.dart';
import 'iso7816/response_apdu.dart';

import '../com/com_provider.dart';
import '../lds/df1/df1.dart';
import '../lds/tlv.dart';
import '../utils.dart';

import 'package:readnfc/extensions.dart';
import 'package:logging/logging.dart';

class MrtdApiError implements Exception {
  final String message;
  final StatusWord? code;
  const MrtdApiError(this.message, {this.code});
  @override
  String toString() => "MRTDApiError: $message";
}

class MrtdApi {
  static const int challengeLen = 8;
  ICC icc;

  MrtdApi(ComProvider com) : icc = ICC(com);

  static const _defaultSelectP2 =
      ISO97816_SelectFileP2.returnFCP | ISO97816_SelectFileP2.returnFMD;
  final _log = Logger("mrtd.api");
  static const int _defaultReadLength = 256;
  int _maxRead = _defaultReadLength;
  static const int _readAheadLength = 8;
  Future<void> Function()? _reinitSession;

  Future<Uint8List> activeAuthenticate(final Uint8List challenge,
      {int sigLength = 256}) async {
    assert(challenge.length == challengeLen);
    _log.debug("Sending AA command with challenge=${challenge.hex()}");
    return await icc.internalAuthenticate(data: challenge, ne: sigLength);
  }

  Future<void> initSessionViaBAC(final DBAKeys keys) async {
    _log.debug("Initiating SM session using BAC protocol");
    await BAC.initSession(dbaKeys: keys, icc: icc);
    _reinitSession = () async {
      _log.debug("Re-initiating SM session using BAC protocol");
      icc.sm = null;
      await BAC.initSession(dbaKeys: keys, icc: icc);
    };
  }

  Future<void> selectEMrtdApplication() async {
    _log.debug("Selecting eMRTD application");
    await icc.selectFileByDFName(dfName: DF1.AID, p2: _defaultSelectP2);
  }

  Future<void> selectMasterFile() async {
    _log.debug("Selecting root Master File");

    await icc
        .selectFile(cla: ISO7816_CLA.NO_SM, p1: 0, p2: 0)
        .onError<ICCError>((error, stackTrace) async {
      _log.warning(
          "Couldn't select MF by P1: 0, P2: 0 sw=${error.sw}, re-trying to select MF with FileID=3F00");
      return await icc
          .selectFile(
              cla: ISO7816_CLA.NO_SM,
              p1: 0,
              p2: 0,
              data: Uint8List.fromList([0x3F, 0x00]))
          .onError<ICCError>((error, stackTrace) async {
        _log.warning(
            "Couldn't select MF by P1=0, P2=0, FileID=3F00 sw=${error.sw}, re-trying to select MF with P2=0x0C and FileID=3F00");
        return await icc
            .selectFileById(
                p2: _defaultSelectP2, fileId: Uint8List.fromList([0x3F, 0x00]))
            .onError<ICCError>((error, stackTrace) async {
          _log.warning(
              "Couldn't select MF by P1=0, P2=0x0C, FileID=3F00 sw=${error.sw}, re-trying to select MF with P2=0x0C");
          return await icc.selectFile(
              cla: ISO7816_CLA.NO_SM, p1: 0, p2: _defaultSelectP2);
        });
      });
    });
  }

  Future<void> selectEFFile(Uint8List fid) async {
    _log.info("Selecting root Element File...........");
    await icc
        .selectFile(cla: ISO7816_CLA.NO_SM, p1: 0x02, p2: 0x0C)
        .onError<ICCError>((error, stackTrace) async {
      _log.warning(
          "Couldn't select MF by P1: 0, P2: 0 sw=${error.sw}, re-trying to select MF with FileID=3F00");
      return await icc
          .selectFile(cla: ISO7816_CLA.NO_SM, p1: 0x02, p2: 0x0C, data: fid)
          .onError<ICCError>((error, stackTrace) async {
        _log.warning(
            "Couldn't select MF by P1=0, P2=0, FileID=3F00 sw=${error.sw}, re-trying to select MF with P2=0x0C and FileID=3F00");
        return await icc
            .selectFileById(
                p2: _defaultSelectP2, fileId: Uint8List.fromList([0x3F, 0x00]))
            .onError<ICCError>((error, stackTrace) async {
          _log.warning(
              "Couldn't select MF by P1=0, P2=0x0C, FileID=3F00 sw=${error.sw}, re-trying to select MF with P2=0x0C");
          return await icc.selectFile(
              cla: ISO7816_CLA.NO_SM, p1: 0, p2: _defaultSelectP2);
        });
      });
    });
  }

  Future<Uint8List> readFile(final int fid) async {
    _log.debug("Reading file fid=0x${Utils.intToBin(fid).hex()}");
    if (fid > 0xFFFF) {
      throw MrtdApiError("Invalid fid=0x${Utils.intToBin(fid).hex()}");
    }

    final efId = Uint8List(2);
    ByteData.view(efId.buffer).setUint16(0, fid);
    await icc.selectEF(efId: efId, p2: _defaultSelectP2);

    final chunk1 = await icc.readBinary(offset: 0, ne: _readAheadLength);
    final dtl = TLV.decodeTagAndLength(chunk1.data!);

    final length = dtl.length.value - (chunk1.data!.length - dtl.encodedLen);
    final chunk2 =
        await _readBinary(offset: chunk1.data!.length, length: length);

    final rawFile = Uint8List.fromList(chunk1.data! + chunk2);
    assert(rawFile.length == dtl.encodedLen + dtl.length.value);
    return rawFile;
  }

  Future<Uint8List> readFileBySFI(int sfi) async {
    _log.debug("Reading file sfi=0x${sfi.hex()}");
    sfi |= 0x80;
    if (sfi > 0x9F) {
      throw ArgumentError.value(sfi, null, "Invalid SFI value");
    }

    final chunk1 =
        await icc.readBinaryBySFI(sfi: sfi, offset: 0, ne: _readAheadLength);
    final dtl = TLV.decodeTagAndLength(chunk1.data!);

    final length = dtl.length.value - (chunk1.data!.length - dtl.encodedLen);
    final chunk2 =
        await _readBinary(offset: chunk1.data!.length, length: length);

    final rawFile = Uint8List.fromList(chunk1.data! + chunk2);
    assert(rawFile.length == dtl.encodedLen + dtl.length.value);
    return rawFile;
  }

  Future<Uint8List> _readBinary(
      {required int offset, required int length}) async {
    var data = Uint8List(0);
    while (length > 0) {
      int nRead = length;
      if (length > _maxRead) {
        nRead = _maxRead;
      }

      _log.debug(
          "_readBinary: offset=$offset nRead=$nRead remaining=$length maxRead=$_maxRead");
      try {
        ResponseAPDU rapdu;
        if (offset > 0x7FFF) {
          rapdu = await icc.readBinaryExt(offset: offset, ne: nRead);
        } else {
          if (offset + nRead > 0x7FFF) {
            nRead = 0x7FFF - offset;
          }
          rapdu = await icc.readBinary(offset: offset, ne: nRead);
        }

        if (rapdu.status.sw1 == StatusWord.sw1SuccessWithRemainingBytes) {
          _log.debug(
              "Received ${rapdu.data?.length ?? 0} byte(s), ${rapdu.status.description()}");
        } else if (rapdu.status == StatusWord.unexpectedEOF) {
          _log.warning(rapdu.status.description());
          _reduceMaxRead();
        } else if (rapdu.status == StatusWord.possibleCorruptedData) {
          _log.warning("Part of received data chunk my be corrupted");
        } else if (rapdu.status.isError()) {
          _log.warning(
              "An error ${rapdu.status} has occurred while reading file but have received some data. Re-initializing SM session and trying to continue normally.");
          await _reinitSession?.call();
        }

        if (rapdu.data != null) {
          data = Uint8List.fromList(data + rapdu.data!);
          offset += rapdu.data!.length;
          length -= rapdu.data!.length;
        } else {
          _log.warning("No data received when trying to read binary");
        }
      } on ICCError catch (e) {
        if (e.sw == StatusWord.wrongLength && _maxRead != 1) {
          _reduceMaxRead();
        } else if (e.sw.sw1 == StatusWord.sw1WrongLengthWithExactLength) {
          _log.warning(
              "Reducing max read to ${e.sw.sw2} byte(s) due to wrong length error");
          _maxRead = e.sw.sw2;
        } else {
          _maxRead = _defaultReadLength;
          throw MrtdApiError(
              "An error has occurred while trying to read file chunk.",
              code: e.sw);
        }
        if (e.sw.isError()) {
          _log.info("Re-initializing SM session due to read binary error");
          await _reinitSession?.call();
        }
      }
    }

    if (length < 0) {
      final newSize = data.length - length.abs();
      _log.warning(
          "Total read data size is greater than requested, removing last ${length.abs()} byte(s)");
      _log.debug(
          "  Requested size:$newSize byte(s) actual size:${data.length} byte(s)");
      data = data.sublist(0, newSize);
    }

    return data;
  }

  void _reduceMaxRead() {
    if (_maxRead > 224) {
      _maxRead = 224; // JMRTD lib's default read size
    } else if (_maxRead > 160) {
      // Some passports can't handle more then 160 bytes per read
      _maxRead = 160;
    } else if (_maxRead > 128) {
      _maxRead = 128;
    } else if (_maxRead > 96) {
      _maxRead = 96;
    } else if (_maxRead > 64) {
      _maxRead = 64;
    } else if (_maxRead > 32) {
      _maxRead = 32;
    } else if (_maxRead > 16) {
      _maxRead = 16;
    } else if (_maxRead > 8) {
      _maxRead = 8;
    } else {
      _maxRead = 1; // last resort try to read 1 byte at the time
    }
    _log.info("Max read changed to: $_maxRead");
  }
}
