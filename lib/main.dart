import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_platform_widgets/flutter_platform_widgets.dart';
import 'package:logging/logging.dart';
import 'package:readnfc/dmrtd.dart';
import 'package:readnfc/extensions.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  final _log = Logger("");
  var _alertMessage = "";
  var _isNfcAvailable = false;
  var _isReading = false;
  final _mrzData = GlobalKey<FormState>();

  MrtdData? _mrtdData;

  final NfcProvider _nfc = NfcProvider();
  final _scrollController = ScrollController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'You have pushed the button this many times:',
            ),
            PlatformTextButton(
              onPressed: _readMRTD,
              child: PlatformText(_isReading ? 'Reading ...' : 'Read'),
            ),
          ],
        ),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }

  void _readMRTD() async {
    try {
      setState(() {
        _mrtdData = null;
        _alertMessage = "Waiting for Passport tag ...";
        _isReading = true;
      });

      await _nfc.connect(
          iosAlertMessage: "Hold your phone near Biometric Passport");
      final passport = Passport(_nfc);

      setState(() {
        _alertMessage = "Reading Passport ...";
        _log.info('Reading Passport ...');
      });

      _nfc.setIosAlertMessage("Trying to read EF.CardAccess ...");
      final mrtdData = MrtdData();

      mrtdData.cardAccess = await passport.readEfCardAccess();

      _log.info("readEfCardAccess: " + mrtdData.cardAccess!.toBytes().hex());

      // _nfc.setIosAlertMessage("Trying to read EF.CardSecurity ...");
      // mrtdData.cardSecurity = await passport.readEfCardSecurity();

      _nfc.setIosAlertMessage("Initiating session ...");
      // final bacKeySeed =
      //     DBAKeys(_docNumber.text, _getDOBDate()!, _getDOEDate()!);
      // await passport.startSession(bacKeySeed);

      // _nfc.setIosAlertMessage(formatProgressMsg("Reading EF.COM ...", 0));
      mrtdData.com = await passport.readEfCOM();

      _log.info("readEfCOM: " + mrtdData.com!.toBytes().hex());

      setState(() {
        _mrtdData = mrtdData;
      });

      setState(() {
        _alertMessage = "";
      });

      _scrollController.animateTo(300.0,
          duration: Duration(milliseconds: 500), curve: Curves.ease);
    } on Exception catch (e) {
      final se = e.toString().toLowerCase();
      String alertMsg = "An error has occurred while reading Passport!";
      if (e is PassportError) {
        if (se.contains("security status not satisfied")) {
          alertMsg =
              "Failed to initiate session with passport.\nCheck input data!";
        }
        _log.error("PassportError: ${e.message}");
      } else {
        _log.error(
            "An exception was encountered while trying to read Passport: $e");
      }

      if (se.contains('timeout')) {
        alertMsg = "Timeout while waiting for Passport tag";
      } else if (se.contains("tag was lost")) {
        alertMsg = "Tag was lost. Please try again!";
      } else if (se.contains("invalidated by user")) {
        alertMsg = "";
      }

      setState(() {
        _alertMessage = alertMsg;
      });
    } finally {
      if (_alertMessage.isNotEmpty) {
        await _nfc.disconnect(iosErrorMessage: _alertMessage);
      } else {
        await _nfc.disconnect(
            // iosAlertMessage: formatProgressMsg("Finished", 100)
            );
      }
      setState(() {
        _isReading = false;
      });
    }
  }
}

class MrtdData {
  EfCardAccess? cardAccess;
  EfCardSecurity? cardSecurity;
  EfCOM? com;
  EfSOD? sod;
  EfDG1? dg1;
  EfDG2? dg2;
  EfDG3? dg3;
  EfDG4? dg4;
  EfDG5? dg5;
  EfDG6? dg6;
  EfDG7? dg7;
  EfDG8? dg8;
  EfDG9? dg9;
  EfDG10? dg10;
  EfDG11? dg11;
  EfDG12? dg12;
  EfDG13? dg13;
  EfDG14? dg14;
  EfDG15? dg15;
  EfDG16? dg16;
  Uint8List? aaSig;
}

final Map<DgTag, String> dgTagToString = {
  EfDG1.TAG: 'EF.DG1',
  EfDG2.TAG: 'EF.DG2',
  EfDG3.TAG: 'EF.DG3',
  EfDG4.TAG: 'EF.DG4',
  EfDG5.TAG: 'EF.DG5',
  EfDG6.TAG: 'EF.DG6',
  EfDG7.TAG: 'EF.DG7',
  EfDG8.TAG: 'EF.DG8',
  EfDG9.TAG: 'EF.DG9',
  EfDG10.TAG: 'EF.DG10',
  EfDG11.TAG: 'EF.DG11',
  EfDG12.TAG: 'EF.DG12',
  EfDG13.TAG: 'EF.DG13',
  EfDG14.TAG: 'EF.DG14',
  EfDG15.TAG: 'EF.DG15',
  EfDG16.TAG: 'EF.DG16'
};
