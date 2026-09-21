#!/usr/bin/env python3
"""A real org.freedesktop.Notifications service, for one call.

internal/deskbus's unit tests drive a fake bus built out of deskbus's OWN
encoder, which proves the client is self-consistent and nothing else. If the
alignment rules are misunderstood, both halves misunderstand them identically
and the test is green.

This is the independent decoder. dbus-daemon parses the message header; this
service, through libdbus's own marshaller, parses the body against the
signature `susssasa{sv}i` and hands back the arguments as Python values. If a
single pad byte is wrong, this fails and the Go test sees an error rather than
a green light.
"""
import json
import sys

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

OUT = sys.argv[1]

class Notifications(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Notifications",
                         in_signature="susssasa{sv}i", out_signature="u")
    def Notify(self, app_name, replaces_id, app_icon, summary, body, actions, hints, expire_timeout):
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump({
                "app_name": str(app_name),
                "replaces_id": int(replaces_id),
                "app_icon": str(app_icon),
                "summary": str(summary),
                "body": str(body),
                "actions": [str(a) for a in actions],
                "hints": {str(k): (int(v) if isinstance(v, (int, dbus.Byte, dbus.UInt32))
                                   else str(v)) for k, v in hints.items()},
                "expire_timeout": int(expire_timeout),
            }, f)
        GLib.timeout_add(300, lambda: (loop.quit(), False)[1])
        return dbus.UInt32(4242)

    @dbus.service.method("org.freedesktop.Notifications",
                         in_signature="", out_signature="ssss")
    def GetServerInformation(self):
        return ("auros-test-notifier", "auros", "1.0", "1.2")

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
name = dbus.service.BusName("org.freedesktop.Notifications", bus)
Notifications(bus, "/org/freedesktop/Notifications")
sys.stderr.write("ready\n")
sys.stderr.flush()
loop = GLib.MainLoop()
loop.run()
