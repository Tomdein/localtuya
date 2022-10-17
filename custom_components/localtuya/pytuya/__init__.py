# PyTuya Module
# -*- coding: utf-8 -*-
"""
Python module to interface with Tuya WiFi smart devices.

Mostly derived from Shenzhen Xenon ESP8266MOD WiFi smart devices
E.g. https://wikidevi.com/wiki/Xenon_SM-PW701U

Author: clach04
Maintained by: postlund

For more information see https://github.com/clach04/python-tuya

Classes
   TuyaInterface(dev_id, address, local_key=None)
       dev_id (str): Device ID e.g. 01234567891234567890
       address (str): Device Network IP Address e.g. 10.0.1.99
       local_key (str, optional): The encryption key. Defaults to None.

Functions
   json = status()          # returns json payload
   set_version(version)     #  3.1 [default] or 3.3
   detect_available_dps()   # returns a list of available dps provided by the device
   update_dps(dps)          # sends update dps command
   add_dps_to_request(dp_index)  # adds dp_index to the list of dps used by the
                                  # device (to be queried in the payload)
   set_dp(on, dp_index)   # Set value of any dps index.


Credits
 * TuyaAPI https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
   For protocol reverse engineering
 * PyTuya https://github.com/clach04/python-tuya by clach04
   The origin of this python module (now abandoned)
 * LocalTuya https://github.com/rospogrigio/localtuya-homeassistant by rospogrigio
   Updated pytuya to support devices with Device IDs of 22 characters
"""