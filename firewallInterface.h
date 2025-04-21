#ifndef FIREWALL_INTERFACE_H
#define FIREWALL_INTERFACE_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QDBusInterface>
#include <QDBusReply>
#include <QVariantMap>
#include <QDBusConnection>
#include <QVector>

// Forward declarations for classes used in FirewallManager
class QDBusInterface;
class QNetworkAccessManager;
class NeuralNetwork;
struct ConnectionState;
struct NetworkFeatures;
struct NetworkTrafficData;

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

class FirewallManager : public QObject {
    Q_OBJECT

public:
    explicit FirewallManager(QObject *parent = nullptr);
    explicit FirewallManager(QDBusConnection &bus, QObject *parent = nullptr);
    ~FirewallManager();

    // Public methods to be called from the GUI
    void enableFirewall();
    void disableFirewall();
    void togglePanicMode();
    void checkInternetConnectivity();
    void blockIPAddress(const QString &ipAddress);
    void unblockIPAddress(const QString &ipAddress);
    void blockWebsite(const QString &website);
    void trainNeuralNetwork();
    void restoreDefaultConfig();
    void optimizeFirewallRules();
    void checkFirewallHealth();
    bool isFirewallEnabled();
    QMap<QString, int> analyzeTraffic();
    bool isInternetConnected();
    
signals:
    void internetStatusChanged(bool status);
    void firewallStatusChanged(bool isEnabled);
    void logMessageGenerated(const QString &message, const QString &logLevel);

private:
    // Private implementation details
    QDBusInterface *firewallInterface;
    QNetworkAccessManager *networkManager;
    std::unique_ptr<NeuralNetwork> neuralNetwork;
    QMap<QString, ConnectionState> connectionTable;
    std::vector<std::vector<double>> trainingData;
    std::vector<std::vector<double>> trainingLabels;
    bool panicModeEnabled;
};

#endif // FIREWALL_INTERFACE_H
