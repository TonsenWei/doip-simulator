[TOC]

# doip-simulator项目说明

此项目从 [https://gitlab.com/rohfle/doip-simulator](https://gitlab.com/rohfle/doip-simulator) fork而来。

## 更新日志
- 2024-03-06: 服务端增加会话服务处理逻辑的模拟

# doip-simulator

A reference server and client implementation for the DoIP (ISO 13400) protocol
used for car diagnostics in modern vehicles

doipclient.py can be used as a starting point for interfacing with the cars sensors
doipserver.py can be used as a simulation to test the client against

doip-simulator was created as part of Luka Bartolec's and Rohan Fletcher's work for Jaguar's
[Race The Pace](https://web.archive.org/web/20200115023337/http://www.racethepace.co.nz/)
campaign run by [True Advertising](http://thisistrue.co/) in NZ 2019/2020

Internal details of Jaguar's vehicle have been replaced with randomized addresses
for public release.

# Requirements
- Python 3.7 or later

# doipserver.py features
- Identity request / announce supports
- Routing activation request simulation
- Diagnostic messages TesterPreset and ReadDataByIdentifier
- Configurable UDS identifier tree with values generated by ramp / step functions
- Error simulation and session recovery

# doipclient.py features
- Identify request / announce broadcasts
- Routing activation
- Configurable UDS identifier tree with custom parsing support
- Error handling and automatic recovery

# Acknowledgements


# License

Copyright 2019 Rohan Fletcher

Copyright 2019 Luka Bartolec

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
