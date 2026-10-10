package keychain

import (
	"errors"
	"slices"

	dbus "github.com/godbus/dbus/v5"
)

// secretsName is the Secret Service's well-known D-Bus name.
const secretsName = "org.freedesktop.secrets"

// available checks for a Secret Service without auto-launching a session
// bus: godbus's SessionBus() runs dbus-launch when DBUS_SESSION_BUS_ADDRESS
// is unset, which on a headless box starts a bus with no keychain on it.
func available() error {
	conn, err := dbus.SessionBusPrivateNoAutoStartup()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Auth(nil); err != nil {
		return err
	}
	if err := conn.Hello(); err != nil {
		return err
	}
	var owned bool
	if err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, secretsName).Store(&owned); err != nil {
		return err
	}
	if owned {
		return nil
	}
	var names []string
	if err := conn.BusObject().Call("org.freedesktop.DBus.ListActivatableNames", 0).Store(&names); err != nil {
		return err
	}
	if !slices.Contains(names, secretsName) {
		return errors.New("no Secret Service (" + secretsName + ") on the session bus")
	}
	return nil
}

// noService recognises the D-Bus error for a missing Secret Service.
func noService(err error) bool {
	var de dbus.Error
	if errors.As(err, &de) {
		return de.Name == "org.freedesktop.DBus.Error.ServiceUnknown" || de.Name == "org.freedesktop.DBus.Error.NameHasNoOwner"
	}
	return false
}
