#ifndef FIREWALL_INTERFACE_H
#define FIREWALL_INTERFACE_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QDBusInterface>
#include <QDBusReply>
#include <QVariantMap>

// This class defines the interface for firewall operations
class FirewallInterface : public QObject {
    Q_OBJECT

public:
    explicit FirewallInterface(QObject *parent = nullptr);
    ~FirewallInterface();

    // Methods to interact with firewall via D-Bus
    bool isRunning();
    bool enable();
    bool disable();
    bool addRule(const QString &action, const QString &direction, const QString &source, 
                 const QString &destination, const QString &protocol);
    bool removeRule(const QString &action, const QString &direction, const QString &source, 
                    const QString &destination, const QString &protocol);
    QStringList listRules();
    QVariantMap getTrafficStatistics();
    bool addPort(const QString &port, const QString &protocol);
    bool removePort(const QString &port, const QString &protocol);
    bool blockIP(const QString &ipAddress);
    bool unblockIP(const QString &ipAddress);
    bool addInterface(const QString &zone, const QString &interface);
    bool removeInterface(const QString &zone, const QString &interface);
    bool changeZoneOfInterface(const QString &zone, const QString &interface);
    bool restoreDefaultConfig();
    bool restartFirewallService();
    QString getFirewallStatus();

private:
    QDBusInterface *interface;
};

#endif // FIREWALL_INTERFACE_H
