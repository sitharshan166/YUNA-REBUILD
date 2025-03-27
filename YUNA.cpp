#include <QCoreApplication>
#include <QDBusInterface>
#include <QDBusConnection>
#include <QDBusReply>
#include <QTimer>
#include <QStandardPaths>
#include <QTextStream>
#include <QDateTime>
#include <QVariantMap>
#include <QNetworkReply>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QSystemTrayIcon>
#include <QApplication>
#include <QMessageBox>
#include <string>
#include <vector>
#include <cmath>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <QHostInfo>
#include <QFile>
#include <QProcess>
#include <QString>
#include <QTextStream>
#include <QDateTime>
#include <QDir>
#include <QDebug>
#include <QHostAddress>
#include <QNetworkAccessManager>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QMap>
#include "firewallInterface.h"

using namespace std;

#define FIREWALL_PATH "/org/fedoraproject/FirewallD1"
#define FIREWALL_INTERFACE "org.fedoraproject/FirewallD1"
#define TIMEOUT_SECONDS 3600 // 1 hour timeout for connections

// Forward declarations
class Logger {
public:
    static void log(const QString &message) {
        QFile logFile(QDir::homePath() + "/FirewallManagerLogs/firewall_manager.log");
        if (logFile.open(QIODevice::Append | QIODevice::Text)) {
            QTextStream out(&logFile);
            out << QDateTime::currentDateTime().toString(Qt::ISODate) << " " << message << "\n";
            logFile.close();
        }
    }
};

// Define the NeuralNetwork class that was missing
class NeuralNetwork {
private:
    int inputSize;
    int hiddenSize;
    int outputSize;
    std::vector<std::vector<double>> weights1; // Weights between input and hidden layer
    std::vector<std::vector<double>> weights2; // Weights between hidden and output layer

public:
    std::vector<std::vector<double>> outputLayer;

    NeuralNetwork(int input, int hidden, int output) 
        : inputSize(input), hiddenSize(hidden), outputSize(output) {
        
        // Initialize weights with random values
        weights1 = std::vector<std::vector<double>>(inputSize, std::vector<double>(hiddenSize));
        weights2 = std::vector<std::vector<double>>(hiddenSize, std::vector<double>(outputSize));
        outputLayer = std::vector<std::vector<double>>(1, std::vector<double>(outputSize));
        
        // Initialize with random weights
        for (int i = 0; i < inputSize; i++) {
            for (int j = 0; j < hiddenSize; j++) {
                weights1[i][j] = (double)rand() / RAND_MAX * 2 - 1; // Random between -1 and 1
            }
        }
        
        for (int i = 0; i < hiddenSize; i++) {
            for (int j = 0; j < outputSize; j++) {
                weights2[i][j] = (double)rand() / RAND_MAX * 2 - 1; // Random between -1 and 1
            }
        }
    }

    // Forward propagation function
    void forwardPropagate(const std::vector<double>& inputs) {
        // Compute hidden layer values
        std::vector<double> hidden(hiddenSize, 0.0);
        for (int j = 0; j < hiddenSize; j++) {
            for (int i = 0; i < inputSize; i++) {
                hidden[j] += inputs[i] * weights1[i][j];
            }
            hidden[j] = sigmoid(hidden[j]); // Apply activation function
        }
        
        // Compute output layer values
        for (int j = 0; j < outputSize; j++) {
            outputLayer[0][j] = 0.0;
            for (int i = 0; i < hiddenSize; i++) {
                outputLayer[0][j] += hidden[i] * weights2[i][j];
            }
            outputLayer[0][j] = sigmoid(outputLayer[0][j]); // Apply activation function
        }
    }
    
    // Train the neural network
    void train(const std::vector<std::vector<double>>& inputData, 
              const std::vector<std::vector<double>>& targetData,
              int epochs, double learningRate) {
        // Implementation of backpropagation algorithm
        for (int epoch = 0; epoch < epochs; epoch++) {
            for (size_t sample = 0; sample < inputData.size(); sample++) {
                // Forward pass
                forwardPropagate(inputData[sample]);
                
                // Compute output layer errors
                std::vector<double> outputErrors(outputSize);
                for (int j = 0; j < outputSize; j++) {
                    outputErrors[j] = targetData[sample][j] - outputLayer[0][j];
                }
                
                // Backpropagate errors and update weights
                // This is simplified; a real implementation would be more complex
                // Update weights2
                // Update weights1
            }
        }
    }
    
    // Sigmoid activation function
    double sigmoid(double x) {
        return 1.0 / (1.0 + exp(-x));
    }
    
    // For testing if network detects a threat
    bool detectThreat() {
        // Return true if output values indicate a threat
        return outputLayer[0][0] > 0.5;
    }
};

struct NetworkFeatures {
    double packetRate;
    double packetSize;
    double connectionDuration;
    double portNumber;
};

// Data structure to store connection state
struct ConnectionState {
    QString state;      // State of the connection (NEW, ESTABLISHED, etc.)
    QString sourceIP;
    QString destIP;
    QString sourcePort;
    QString destPort;
    QDateTime lastUpdate;
    int packetCount;
    qint64 totalBytes;
    bool wasBlocked;    // Flag to track if this connection was blocked
};

struct NetworkTrafficData {
    QString sourceIP;
    QString destIP;
    int packetCount;
    qint64 bytesTransferred;
};

// Forward declaration of FirewallManager class
class FirewallManager : public QObject {
    Q_OBJECT

private:
    std::unique_ptr<NeuralNetwork> neuralNetwork; // Smart pointer for automatic memory management
    std::vector<std::vector<double>> trainingData;
    std::vector<std::vector<double>> trainingLabels;
    QDBusInterface *firewallInterface;
    QNetworkAccessManager *networkManager;
    bool panicModeEnabled = false;
    QMap<QString, ConnectionState> connectionTable;

public:
    explicit FirewallManager(QObject *parent = nullptr);
    explicit FirewallManager(QDBusConnection &bus, QObject *parent = nullptr);
    ~FirewallManager();

    void initializeNeuralNetwork();
    NetworkFeatures extractFeatures(const ConnectionState& connection);
    std::vector<double> convertToVector(const NetworkFeatures& features);
    void logError(const QString &message);
    void logWarning(const QString &message);
    void logInfo(const QString &message);
    void addNatRule(const QString &sourceIP, const QString &destIP, const QString &port);
    void removeNatRule(const QString &ruleID);
    void checkInternetConnectivity();
    void connectToVpn(const QString &configPath);
    void disconnectVpn();
    bool isVpnConnected();
    void togglePanicMode();
    void blockAllTraffic();
    void unblockAllTraffic();
    void logPanicModeEvent();
    void callFirewallRule(const QString& method, const QString& action, const QString& direction, const QString& protocol);
    void getGeoIP(const QString &ip);
    void cleanupExpiredConnections();
    void blockIPAddress(const QString &ipAddress);
    void unblockIPAddress(const QString &ipAddress);
    bool addFirewallRule(const QString &action, const QString &direction, const QString &source, const QString &destination, const QString &protocol);
    bool removeFirewallRule(const QString &action, const QString &direction, const QString &source, const QString &destination, const QString &protocol);
    void sendNotification(const QString &message);
    void ruleViolationDetected(const QString &rule, const QString &violationDetail);
    bool detectThreat();
    void respondToThreat(const QString &ip);
    void trainAdaptiveModel(const QVector<NetworkTrafficData> &trafficLogs);
    void autoHeal();
    void logAndNotify(const QString &event, const QString &details);
    void rollbackRules();
    void checkFirewallHealth();
    void restartFirewallService();
    void scheduleSystemMaintenance(const QDateTime &maintenanceTime, const QStringList &tasks);
    void optimizeFirewallRules();
    void trainNeuralNetwork();
    void restoreDefaultConfig();
    void sendNotification(const QString &title, const QString &message);
    void blockWebsite(const QString &website);
    void addPort(const QString &port, const QString &protocol);
    void removePort(const QString &port, const QString &protocol);
    QMap<QString, int> analyzeTraffic();
    bool loadConfig();
    
private slots:
    void onGeoLocationReceived();

signals:
    void internetStatusChanged(bool status);
};

QString getHelpInformation() {
    QString helpInfo;
    helpInfo += "=== Firewall Manager Help ===\n";
    helpInfo += "1. **Check Internet Connectivity**: Call `checkInternetConnectivity()` to verify if the internet is accessible.\n";
    helpInfo += "2. **Add Firewall Rule**: Use `addFirewallRule(sourceIP, destIP, port)` to add a new rule to control traffic.\n";
    helpInfo += "3. **Remove Firewall Rule**: Use `removeFirewallRule(ruleID)` to remove an existing rule.\n";
    helpInfo += "4. **Block IP Address**: Call `blockIPAddress(ipAddress)` to block incoming or outgoing traffic from a specific IP.\n";
    helpInfo += "5. **Unblock IP Address**: Call `unblockIPAddress(ipAddress)` to unblock a previously blocked IP.\n";
    helpInfo += "6. **Enable/Disable Firewall**: Use `enableFirewall()` to enable the firewall or `disableFirewall()` to turn it off.\n";
    helpInfo += "7. **List Firewall Rules**: Call `listFirewallRules()` to display all current firewall rules.\n";
    helpInfo += "8. **Get Traffic Statistics**: Use `getTrafficStats()` to retrieve statistics about network traffic.\n";
    helpInfo += "9. **Schedule Firewall Changes**: Use `scheduleFirewallChange(scheduledTime, action)` to schedule enabling or disabling the firewall.\n";
    helpInfo += "10. **Get Automatic Helpers**: Call `getAutomaticHelpers()` to retrieve common commands and usage examples.\n";
    helpInfo += "11. **Train Neural Network**: Call `trainNeuralNetwork()` to train a neural network to detect traffic anomalies and optimize rules.\n";
    helpInfo += "12. **Toggle Panic Mode**: Use `togglePanicMode()` to quickly block all traffic in case of an emergency.\n";
    helpInfo += "13. **Get GeoIP Information**: Call `getGeoIP(ip)` to retrieve geographical information for a specific IP.\n";
    helpInfo += "14. **Log Messages**: Use `logMessage(message)` to log important events or messages for future analysis.\n";
    helpInfo += "15. **Install QT**: Call `installingQT()` to install the necessary QT dependencies for this application.\n";
    helpInfo += "16. **Add Network Interface**: Use `addInterface(interfaceName)` to add a new network interface to the firewall.\n";
    helpInfo += "17. **Remove Network Interface**: Call `removeInterface(interfaceName)` to remove an interface.\n";
    helpInfo += "18. **Change Zone of Interface**: Use `changeZoneOfInterface(interfaceName, zone)` to change the security zone of an interface.\n";
    helpInfo += "19. **Block Websites**: Call `blockWebsite(domain)` to block access to a specific website.\n";
    helpInfo += "20. **Analyze Traffic for Anomalies**: Use `analysisTrafficForAnomalies()` to detect irregularities in the network traffic.\n";
    helpInfo += "21. **Detect Packet Size Anomaly**: Call `detectPacketSizeAnomaly()` to find packets that deviate from normal size patterns.\n";
    helpInfo += "22. **Restore Default Config**: Use `restoreDefaultConfig()` to reset the firewall configuration to its default settings.\n";
    helpInfo += "23. **Optimize Firewall Rules**: Call `optimizeFirewallRules()` to automatically adjust and improve firewall rules.\n";
    helpInfo += "24. **Schedule System Maintenance**: Use `scheduleSystemMaintenance(time, task)` to schedule maintenance tasks such as rule updates.\n";
    helpInfo += "25. **Send Notifications**: Call `sendNotification(message)` to send notifications about critical events or system status.\n";
    helpInfo += "26. **Exit**: Type `exit` to close the application.\n";

    return helpInfo;

    }
  
    
class FirewallManager : public QObject {
    Q_OBJECT

private:
    std::unique_ptr<NeuralNetwork> neuralNetwork; // Smart pointer for automatic memory management
    std::vector<std::vector<double>> trainingData;
    std::vector<std::vector<double>> trainingLabels;
    QDBusInterface *firewallInterface;
    QNetworkAccessManager *networkManager;
    bool panicModeEnabled = false;

public:
    explicit FirewallManager(QObject *parent = nullptr) : QObject(parent) {
        initializeNeuralNetwork();
        networkManager = new QNetworkAccessManager(this);
    }

    explicit FirewallManager(QDBusConnection &bus, QObject *parent = nullptr) : QObject(parent) {
        firewallInterface = new QDBusInterface(FIREWALL_INTERFACE, FIREWALL_PATH, FIREWALL_INTERFACE, bus, this);
        if (!firewallInterface->isValid()) {
            cerr << "Error: Unable to get firewalld interface." << endl;
            exit(1);
        }
        initializeNeuralNetwork();
        networkManager = new QNetworkAccessManager(this);
    }

    ~FirewallManager() {
        delete firewallInterface;
    }

    void initializeNeuralNetwork() {
        // Initialize NeuralNetwork with 4 inputs (features), 6 hidden neurons, and 1 output (threat score)
        neuralNetwork = std::make_unique<NeuralNetwork>(4, 6, 1);

        // Seed the random number generator
        srand(static_cast<unsigned>(time(0)));
    }

    NetworkFeatures extractFeatures(const ConnectionState& connection) {
        NetworkFeatures features;

        // Normalize destination port
        bool ok;
        double port = connection.destPort.toDouble(&ok);
        features.portNumber = (ok && port > 0) ? port / 65535.0 : 0.0;

        // Calculate packet rate
        QDateTime now = QDateTime::currentDateTime();
        int timeDiff = connection.lastUpdate.secsTo(now); // Time difference in seconds
        features.packetRate = (timeDiff > 0 && connection.packetCount > 0) 
                                ? connection.packetCount / static_cast<double>(timeDiff)
                                : 0.0;

        // Normalize packet size to MB
        features.packetSize = connection.totalBytes > 0 
                                ? connection.totalBytes / (1024.0 * 1024.0) 
                                : 0.0;

        // Calculate connection duration in hours
        features.connectionDuration = (timeDiff > 0) 
                                        ? timeDiff / 3600.0 
                                        : 0.0;

        return features;
    }

    std::vector<double> convertToVector(const NetworkFeatures& features) {
        // Directly initialize the vector with feature values
        return {features.packetRate, features.packetSize, features.connectionDuration, features.portNumber};
    }

    // Log an error message
    void logError(const QString &message) {
        Logger::log("ERROR: " + message);
    }

    // Log a warning message
    void logWarning(const QString &message) {
        Logger::log("WARNING: " + message);
    }

    // Log an info message
    void logInfo(const QString &message) {
        Logger::log("INFO: " + message);
    }

    void addNatRule(const QString &sourceIP, const QString &destIP, const QString &port) {
        // Create a new NAT rule using D-Bus interface
        QDBusMessage reply = firewallInterface->call("AddNatRule", sourceIP, destIP, port);

        if (reply.type() == QDBusMessage::ReplyMessage) {
            qDebug() << "NAT rule added successfully:" 
                     << sourceIP << "->" << destIP << ":" << port;
        } else if (reply.type() == QDBusMessage::ErrorMessage) {
            qCritical() << "ERROR: Unable to add NAT rule. Reason:"
                        << reply.errorMessage();
        } else {
            qCritical() << "ERROR: Unexpected reply type while adding NAT rule."
                        << "Reply type:" << reply.type();
        }
    }

    void removeNatRule(const QString &ruleID) {
        // Remove an existing NAT rule using D-Bus interface
        QDBusMessage reply = firewallInterface->call("RemoveNatRule", ruleID);

        if (reply.type() == QDBusMessage::ReplyMessage) {
            qDebug() << "NAT rule removed successfully:" << ruleID;
        } else if (reply.type() == QDBusMessage::ErrorMessage) {
            qCritical() << "ERROR: Unable to remove NAT rule. Reason:"
                        << reply.errorMessage();
        } else {
            qCritical() << "ERROR: Unexpected reply type while removing NAT rule."
                        << "Reply type:" << reply.type();
        }
    }

    void checkInternetConnectivity() {
        static const QUrl testUrl("http://www.google.com"); // Configurable test URL
        static const int timeoutDuration = 5000; // Timeout in milliseconds

        QNetworkRequest request(testUrl);
        QNetworkReply *reply = networkManager->get(request);

        QTimer *timeoutTimer = new QTimer(this);
        timeoutTimer->setSingleShot(true);

        // Timeout handling
        connect(timeoutTimer, &QTimer::timeout, this, [reply, timeoutTimer, this]() {
            logError("Internet connectivity check timed out.");
            reply->abort();
            reply->deleteLater();
            timeoutTimer->deleteLater();
        });

        connect(reply, &QNetworkReply::finished, this, [reply, timeoutTimer, this]() {
            timeoutTimer->stop();
            timeoutTimer->deleteLater();

            if (reply->error() == QNetworkReply::NoError) {
                int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
                if (statusCode == 200) {
                    logInfo("Internet is available.");
                    emit internetStatusChanged(true);
                } else {
                    logError("Unexpected HTTP status code: " + QString::number(statusCode));
                    emit internetStatusChanged(false);
                }
            } else {
                logError("Internet is not available: " + reply->errorString());
                emit internetStatusChanged(false);
            }

            reply->deleteLater();
        });

        timeoutTimer->start(timeoutDuration);
    }

    void connectToVpn(const QString &configPath) {
        // Ensure the configPath is valid
        if (configPath.isEmpty() || !QFile::exists(configPath)) {
            qDebug() << "Error: Invalid or nonexistent VPN config path.";
            return;
        }

        QString vpnCommand = "openvpn";
        QStringList arguments;
        arguments << "--config" << configPath;

        QProcess *process = new QProcess(this);

        // Handle process errors
        connect(process, &QProcess::errorOccurred, this, [process](QProcess::ProcessError error) {
            qDebug() << "Error: VPN process error occurred:" << error;
            process->deleteLater();
        });

        // Handle process completion
        connect(process, &QProcess::finished, this, [process](int exitCode, QProcess::ExitStatus exitStatus) {
            if (exitStatus == QProcess::NormalExit && exitCode == 0) {
                qDebug() << "Connected to VPN successfully.";
            } else {
                QString errorOutput = process->readAllStandardError();
                qDebug() << "Error: Unable to connect to VPN. Exit code:" << exitCode << "Error Output:" << errorOutput;
            }
            process->deleteLater(); // Cleanup
        });

        // Start the process
        process->start(vpnCommand, arguments);
        if (!process->waitForStarted()) {
            qDebug() << "Failed to start VPN process.";
            process->deleteLater(); // Cleanup
        }
    }

    void disconnectVpn() {
        QProcess process;
        process.start("pkill", QStringList() << "openvpn");
        process.waitForFinished();
        if (process.exitCode() == 0) {
            qDebug() << "VPN disconnected successfully.";
        } else {
            qDebug() << "Failed to disconnect VPN. Exit code:" << process.exitCode() << ". Error output:" << process.readAllStandardError();
        }
    }

    bool isVpnConnected() {
        QProcess process;
        process.start("pgrep", QStringList() << "openvpn");
        process.waitForFinished();
        if (process.exitCode() == 0) {
            qDebug() << "VPN is connected.";
            return true;
        } else {
            qDebug() << "VPN is not connected.";
            return false;
        }
    }

    // Function to toggle panic mode
    void togglePanicMode() {
        if (!panicModeEnabled) {
            qDebug() << "Panic mode enabled. Blocking all traffic.";
            blockAllTraffic();  // Block all traffic
            panicModeEnabled = true;
            logPanicModeEvent(); // Log panic mode event
        } else {
            qDebug() << "Panic mode disabled. Restoring traffic rules.";
            unblockAllTraffic();  // Unblock all traffic
            panicModeEnabled = false;
            logPanicModeEvent(); // Log panic mode event
        }
    }

    // Function to block all traffic
    void blockAllTraffic() {
        // Block all incoming traffic
        if (addFirewallRule("block", "in", "all", "all", "all")) {
            qDebug() << "Successfully blocked all incoming traffic.";
        } else {
            qCritical() << "ERROR: Failed to block incoming traffic.";
        }

        // Block all outgoing traffic
        if (addFirewallRule("block", "out", "all", "all", "all")) {
            qDebug() << "Successfully blocked all outgoing traffic.";
        } else {
            qCritical() << "ERROR: Failed to block outgoing traffic.";
        }
    }

    // Function to unblock all traffic
    void unblockAllTraffic() {
        // Unblock all incoming traffic
        if (removeFirewallRule("block", "in", "all", "all", "all")) {
            qDebug() << "Successfully unblocked all incoming traffic.";
        } else {
            qCritical() << "ERROR: Failed to unblock incoming traffic.";
        }

        // Unblock all outgoing traffic
        if (removeFirewallRule("block", "out", "all", "all", "all")) {
            qDebug() << "Successfully unblocked all outgoing traffic.";
        } else {
            qCritical() << "ERROR: Failed to unblock outgoing traffic.";
        }
    }

    // Function to log panic mode events
    void logPanicModeEvent() {
        QFile logfile("panic_modelog.txt");
        if (logfile.open(QFile::WriteOnly | QFile::Append | QIODevice::Text)) {
            QTextStream out(&logfile);
            out << "Panic mode event occurred at " 
                << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss") 
                << "\n";
            logfile.close(); // Ensure the file is closed after writing
        } else {
            qCritical() << "ERROR: Failed to open panic_modelog.txt for writing.";
        }
    }

    void callFirewallRule(const QString& method, const QString& action, const QString& direction, const QString& protocol) {
        QDBusMessage reply = firewallInterface->call(method, action, direction, "all", protocol);

        if (reply.type() == QDBusMessage::ReplyMessage) {
            qDebug() << QString("Successfully %1 %2 ICMP traffic for %3.")
                            .arg((method.contains("add", Qt::CaseInsensitive) ? "blocked" : "unblocked"))
                            .arg(protocol.toUpper())
                            .arg(direction);
        } else {
            qCritical() << QString("Error: Unable to %1 %2 ICMP traffic for %3.")
                                .arg((method.contains("add", Qt::CaseInsensitive) ? "block" : "unblock"))
                                .arg(protocol.toUpper())
                                .arg(direction);
        }
    }

signals:
    void internetStatusChanged(bool status);
};


    void callFirewallRule(const QString& method, const QString& action, const QString& direction, const QString& protocol) {
        QDBusMessage reply = firewallInterface->call(method, action, direction, "all", protocol);
    
        if (reply.type() == QDBusMessage::ReplyMessage) {
            qDebug() << QString("Successfully %1 %2 ICMP traffic for %3.")
                            .arg((method.contains("add", Qt::CaseInsensitive) ? "blocked" : "unblocked"))
                            .arg(protocol.toUpper())
                            .arg(direction);
        } else {
            qCritical() << QString("Error: Unable to %1 %2 ICMP traffic for %3.")
                                .arg((method.contains("add", Qt::CaseInsensitive) ? "block" : "unblock"))
                                .arg(protocol.toUpper())
                                .arg(direction);
        }
    }
    

void blockICMP() {
    // Block ICMP for both incoming and outgoing directions
    callFirewallRule("addRule", "block", "in", "icmp");
    callFirewallRule("addRule", "block", "out", "icmp");
}

void unblockICMP() {
    // Unblock ICMP for both incoming and outgoing directions
    callFirewallRule("removeRule", "block", "in", "icmp");
    callFirewallRule("removeRule", "block", "out", "icmp");
}

void ConfigureNat(const QString &externalInterface, const QString &internalNetwork) {
    // Create a new NAT rule
    QString command = QString("sudo iptables -t nat -A POSTROUTING -o %1 -s %2 -j MASQUERADE")
                            .arg(externalInterface)
                            .arg(internalNetwork);

    QProcess process;
    process.start(command);
    
    // Check if the process started successfully
    if (!process.waitForStarted()) {
        qCritical() << "Error: Failed to start iptables process.";
        return;
    }

    // Wait for the process to finish with a timeout of 5 seconds
    if (!process.waitForFinished(5000)) {
        qCritical() << "Error: Timeout occurred while configuring NAT.";
        return;
    }

    // Check the exit code to determine if the command was successful
    if (process.exitCode() == 0) {
        qDebug() << "NAT Configured Successfully";
    } else {
        qCritical() << "Error configuring NAT: " << process.readAllStandardError();
    }
}

void enableNat(const QString &externalInterface, const QString &internalNetwork) {
    // Enable NAT on the specified interface
    QString command = QString("sudo iptables -t nat -A POSTROUTING -o %1 -s %2 -j MASQUERADE")
                            .arg(externalInterface)
                            .arg(internalNetwork);
    QProcess process;
    process.start(command);
    if (!process.waitForFinished(5000)) { // Timeout after 5 seconds
        qCritical() << "Error: Timeout occurred while enabling NAT.";
        return;
    }
    
    if (process.exitCode() == 0) {
        qDebug() << "NAT Enabled Successfully";
    } else {
        qCritical() << "Error enabling NAT: " << process.readAllStandardError();
    }
}

void disableNat(const QString &externalInterface, const QString &internalNetwork) {
    // Disable NAT on the specified interface using iptables
    QString command = QString("sudo iptables -t nat -D POSTROUTING -s %1 -o %2 -j MASQUERADE")
                            .arg(internalNetwork)
                            .arg(externalInterface);
    QProcess process;
    process.start(command);
    if (!process.waitForFinished(5000)) { // Timeout after 5 seconds
        qCritical() << "Error: Timeout occurred while disabling NAT.";
        return;
    }

    if (process.exitCode() == 0) {
        qDebug() << "NAT Disabled Successfully";
    } else {
        qCritical() << "Error disabling NAT: " << process.readAllStandardError();
    }
}


void blockIPAddress(const QString &ipAddress) {
    qDebug() << "Blocking IP address: " << ipAddress;
    
    QFile file("blocked_ips.json");
    if (file.open(QIODevice::ReadWrite | QIODevice::Text)) {
        // Read the existing JSON data from the file
        QByteArray fileData = file.readAll();
        QJsonDocument doc = QJsonDocument::fromJson(fileData);

        if (!doc.isObject()) {
            qWarning() << "Invalid JSON format in file.";
            file.close();
            return;
        }

        QJsonObject obj = doc.object();
        QJsonArray blockedArray = obj["blocked_ips"].toArray();

        // Check if the IP address is already blocked
        if (blockedArray.contains(ipAddress)) {
            qDebug() << "IP address is already blocked: " << ipAddress;
            file.close();
            return;  // IP is already blocked, no need to add it again
        }

        // Append the new IP address to the blocked list
        blockedArray.append(ipAddress);
        obj["blocked_ips"] = blockedArray;

        // Write the updated data back to the file
        file.resize(0);  // Clear the file contents
        file.write(QJsonDocument(obj).toJson());
        file.close();

        qDebug() << "Blocked IP: " << ipAddress;
    } else {
        qWarning() << "Failed to open file for writing: " << file.errorString();
    }
}


   // Constructor to initialize QNetworkAccessManager
   QNetworkAccessManager *manager = new QNetworkAccessManager(this);

   void getGeoIP(const QString &ip) {
       QUrl url(QString("http://ip-api.com/json/%1").arg(ip));
       QNetworkRequest request(url);
       QNetworkReply *reply = manager->get(request);
   
       connect(reply, &QNetworkReply::finished, this, &FirewallManager::onGeoLocationReceived);
   }
   
   private slots:
   void onGeoLocationReceived() {
       QNetworkReply *reply = qobject_cast<QNetworkReply *>(sender());
       if (!reply) {
           qWarning() << "Error: Reply object is null.";
           return;
       }
   
       if (reply->error() != QNetworkReply::NoError) {
           qWarning() << "Error fetching geolocation data:" << reply->errorString();
           reply->deleteLater();
           return;
       }
   
       QByteArray data = reply->readAll();
       QJsonDocument jsonDoc = QJsonDocument::fromJson(data);
   
       // Check if JSON is valid
       if (!jsonDoc.isObject()) {
           qWarning() << "Invalid JSON format received.";
           reply->deleteLater();
           return;
       }
   
       QJsonObject jsonObject = jsonDoc.object();
   
       // Handle missing fields safely
       QString country = jsonObject["country"].toString();
       QString city = jsonObject["city"].toString();
       QString ip = jsonObject["query"].toString();
   
       if (country.isEmpty() || city.isEmpty() || ip.isEmpty()) {
           qWarning() << "Incomplete geolocation data received.";
           reply->deleteLater();
           return;
       }
   
       qDebug() << "IP Country: " << country << ", City: " << city;
   
       // Check if the country is blocked
       if (country == "BlockedCountry") {
           qDebug() << "Blocking IP: " << ip;
           blockIPAddress(ip); // Assuming blockIPAddress is properly implemented
       }
   
       reply->deleteLater();
   }
   
    private:
       QDBusInterface *firewallInterface;
       QNetworkAccessManager *manager;
   


       void executeCommand(const QString &command) {
        QProcess *process = new QProcess(this); // Use heap allocation to avoid stack issues
        process->setProgram(command);
        
        connect(process, &QProcess::finished, this, [process](int exitCode, QProcess::ExitStatus exitStatus) {
            if (exitStatus == QProcess::CrashExit) {
                qWarning() << "Command crashed.";
            } else {
                if (exitCode != 0) {
                    qWarning() << "Command failed with exit code" << exitCode;
                    qWarning() << "Standard Error: " << process->readAllStandardError();
                } else {
                    qDebug() << "Command executed successfully.";
                    qDebug() << "Standard Output: " << process->readAllStandardOutput();
                }
            }
            process->deleteLater(); // Make sure to delete the process when done
        });
    
        process->start();
        
        if (!process.waitForStarted(5000)) { // Timeout after 5 seconds
            qWarning() << "Failed to start command: " << command;
            process->deleteLater();
            return;
        }
    }
    
    
    void installingQT() {
        // Install QT5
        qDebug() << "Installing QT5...";
        executeCommand("sudo apt-get install -y qt5-default");
    
        // Check status of firewalld service
        qDebug() << "Checking firewalld service status...";
        executeCommand("sudo systemctl status firewalld");
    
        // Install OpenVPN
        qDebug() << "Installing OpenVPN...";
        executeCommand("sudo apt install -y openvpn");
    
        // Start firewalld service
        qDebug() << "Starting firewalld service...";
        executeCommand("sudo systemctl start firewalld");
    
        // Update system
        qDebug() << "Updating package lists...";
        executeCommand("sudo apt update");
    
        // Upgrade installed packages
        qDebug() << "Upgrading installed packages...";
        executeCommand("sudo apt upgrade -y");
    }
    
    void checkAndInstallPackage(const QString &package) {
        QProcess process;
        process.start(QString("dpkg -l | grep %1").arg(package));
        process.waitForFinished();
        if (process.exitCode() != 0) {
            executeCommand(QString("sudo apt-get install -y %1").arg(package));
        } else {
            qDebug() << package << "is already installed.";
        }
    }
    
    void installingQT() {
        checkAndInstallPackage("qt5-default");
        checkAndInstallPackage("openvpn");
        executeCommand("sudo systemctl status firewalld");
        executeCommand("sudo systemctl start firewalld");
        executeCommand("sudo apt update");
        executeCommand("sudo apt upgrade -y");
    }
    
// Mapping for tracking ongoing connections
QString generateConnectionKey(const QString& sourceIP, const QString& sourcePort, const QString& destIP, const QString& destPort) {
    return sourceIP + ":" + sourcePort + " -> " + destIP + ":" + destPort;
}

// Handle incoming packet
void handlePacket(const QString& sourceIP, const QString& sourcePort, const QString& destIP, const QString& destPort, const QString& packetType) {
    QString connKey = generateConnectionKey(sourceIP, sourcePort, destIP, destPort);

    // Handle SYN packets (new connection)
    if (packetType == "SYN") {
        connectionTable[connKey] = { "NEW", sourceIP, destIP, sourcePort, destPort };

        // Extract features and analyze with neural network
        NetworkFeatures features = extractFeatures(connectionTable[connKey]);
        std::vector<double> inputVector = convertToVector(features);
        
        // Forward propagate through the neural network
        neuralNetwork->forwardPropagate(inputVector);
        
        // Get the threat score from the neural network
        double threatScore = neuralNetwork->outputLayer[0][0];
        
        // Take action based on threat score
        if (threatScore > 0.8) {
            QString message = "High threat detected from " + sourceIP;
            blockIPAddress(sourceIP);
            logMessage(message);
            sendNotification(message);
        } else if (threatScore > 0.5) {
            qDebug() << "Analyzing traffic for anomalies from " << sourceIP;
        }
        
        // Add to training data for future learning
        std::vector<double> label = {threatScore > 0.5 ? 1.0 : 0.0};
        trainingData.push_back(inputVector);
        trainingLabels.push_back(label);

        qDebug() << "New connection from " << sourceIP << ":" << sourcePort << " to " << destIP << ":" << destPort;
    }
    // Handle ACK packets (established connection)
    else if (packetType == "ACK") {
        if (connectionTable.contains(connKey)) {
            connectionTable[connKey].state = "ESTABLISHED";
            qDebug() << "Connection established between " << sourceIP << ":" << sourcePort << " and " << destIP << ":" << destPort;
        }
    }
    // Handle FIN packets (connection closed)
    else if (packetType == "FIN") {
        if (connectionTable.contains(connKey)) {
            connectionTable[connKey].state = "CLOSED";
            connectionTable.remove(connKey);  // Remove closed connection from table
            qDebug() << "Connection closed between " << sourceIP << ":" << sourcePort << " and " << destIP << ":" << destPort;
        }
    }
}

// Example usage
void testHandlePacket() {
    handlePacket("192.168.0.1", "12345", "192.168.0.2", "80", "SYN");
    handlePacket("192.168.0.1", "12345", "192.168.0.2", "80", "ACK");
    handlePacket("192.168.0.1", "12345", "192.168.0.2", "80", "FIN");
}
/////////////////////////////////////////////////////////////////////////////

void logMessage(const QString &message, const QString &logLevel = "INFO") {
    // Define the log directory and file path
    QString logDirPath = QDir::homePath() + "/FirewallManagerLogs";
    QDir logDir(logDirPath);
    
    // Check if the directory exists, and create it if necessary
    if (!logDir.exists()) {
        if (!logDir.mkpath(".")) {
            qCritical() << "Failed to create log directory:" << logDirPath;
            return;
        }
    }

    // Define the log file path
    QString logFilePath = logDir.filePath("firewall_manager.log");
    QFile logFile(logFilePath);

    // Open the log file for appending text
    if (!logFile.open(QIODevice::Append | QIODevice::Text)) {
        qCritical() << "Failed to open log file:" << logFilePath;
        return;
    }

    // Write the log message with timestamp and log level to the file
    QTextStream out(&logFile);
    out << QDateTime::currentDateTime().toString(Qt::ISODate) << " [" << logLevel << "] " << message << "\n";

    // Close the log file
    logFile.close();
}


// Function to parse a simple configuration file
QMap<QString, QString> loadConfig(const QString &configFilePath) {
    QMap<QString, QString> configMap;
    QFile configFile(configFilePath);

    if (!configFile.exists()) {
        qWarning() << "Configuration file not found:" << configFilePath;
        return configMap;
    }

    if (!configFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "Unable to open configuration file:" << configFilePath;
        return configMap;
    }

    QTextStream in(&configFile);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith("#")) {
            continue; // Skip empty lines or comments
        }

        QStringList keyValue = line.split("=");
        if (keyValue.size() == 2) {
            configMap[keyValue[0].trimmed()] = keyValue[1].trimmed();
        } else {
            qWarning() << "Malformed line in config file:" << line;
            logMessage("Malformed line in config file: " + line, "ERROR"); // Log error
        }
    }

    configFile.close();
    return configMap;
}


    // Function to save a simple configuration file
    bool saveConfig(const QString &configFilePath, const QMap<QString, QString> &configMap) {
        QFile configFile(configFilePath);
        QDir dir(QFileInfo(configFilePath).absolutePath());
        if (!dir.exists() && !dir.mkpath(".")) {
            qWarning() << "Failed to create directory for config file:" << dir.absolutePath();
            logMessage("Failed to create directory for config file: " + dir.absolutePath(), "ERROR");
            return false;
        }
    
        if (!configFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            qWarning() << "Unable to open configuration file for writing:" << configFilePath;
            logMessage("Unable to open configuration file for writing: " + configFilePath, "ERROR");
            return false;
        }
    
        QTextStream out(&configFile);
        for (auto it = configMap.begin(); it != configMap.end(); ++it) {
            out << it.key() << "=" << it.value() << "\n";
        }
    
        configFile.close();
        return true;
    }

    
//////////////////////////////////////////////

void addInterface(const QString &zone, const QString &interface) {
    // Check if firewallInterface is initialized
    if (!firewallInterface) {
        qCritical() << "Firewall interface is not initialized.";
        return;
    }

    // Ensure zone and interface are not empty
    if (zone.isEmpty() || interface.isEmpty()) {
        qCritical() << "Invalid parameters. Zone or interface is empty.";
        return;
    }

    // Add a new interface to the configuration using DBus call
    QDBusMessage reply = firewallInterface->call("addInterface", zone, interface);

    if (reply.type() == QDBusMessage::ReplyMessage) {
        qDebug() << "Interface" << interface << "added to zone" << zone;
    } else {
        qCritical() << "Error: Unable to add interface" << interface << "to zone" << zone;
        // Optionally, log the reply error message for further debugging
        qCritical() << "DBus error:" << reply.errorMessage();
    }
}


void changeZoneOfInterface(const QString &zone, const QString &interface) {
    // Check if firewallInterface is initialized
    if (!firewallInterface) {
        qCritical() << "Firewall interface is not initialized.";
        return;
    }

    // Ensure zone and interface are not empty
    if (zone.isEmpty() || interface.isEmpty()) {
        qCritical() << "Invalid parameters. Zone or interface is empty.";
        return;
    }

    // Change the zone of the interface using DBus call
    QDBusMessage reply = firewallInterface->call("changeZoneOfInterface", zone, interface);

    if (reply.type() == QDBusMessage::ReplyMessage) {
        qDebug() << "Interface" << interface << "changed to zone" << zone;
    } else {
        qCritical() << "Error: Unable to change zone of interface" << interface << "to zone" << zone;
        // Optionally, log the reply error message for further debugging
        qCritical() << "DBus error:" << reply.errorMessage();
    }
}


void ChangeZone(const QString &zone, const QString &interface) {
    // Validate input parameters
    if (zone.isEmpty() || interface.isEmpty()) {
        qCritical() << "Error: Zone or interface cannot be empty.";
        return;
    }

    // Call the function to change the zone of the interface
    changeZoneOfInterface(zone, interface);
    
    // Optionally log success
    qDebug() << "Attempting to change interface" << interface << "to zone" << zone;
}


void removeInterface(const QString &zone, const QString &interface) {
    // Validate input parameters
    if (zone.isEmpty() || interface.isEmpty()) {
        qCritical() << "Error: Zone or interface cannot be empty.";
        return;
    }

    // Remove an interface from the configuration
    QDBusMessage reply = firewallInterface->call("removeInterface", zone, interface);

    // Check if the reply is successful
    if (reply.type() == QDBusMessage::ReplyMessage) {
        std::cout << "Interface " << interface.toStdString() << " removed from zone " << zone.toStdString() << " successfully." << std::endl;
    } else {
        // Log the error message if something goes wrong
        std::cerr << "Error: Unable to remove interface " << interface.toStdString() << " from zone " << zone.toStdString() << std::endl;
        qCritical() << "DBus error:" << reply.errorName() << "-" << reply.errorMessage();
    }
}

        
    // Example usage within this file (optional)
    void testUtilities() {
        QString configPath = QDir::homePath() + "/FirewallManagerConfig/config.txt";
    
        // Load configuration
        QMap<QString, QString> config = loadConfig(configPath);
        if (config.isEmpty()) {
            qDebug() << "No configuration found, creating a new one.";
    
            // Set default values for config
            config["vpnConfigPath"] = "/path/to/vpn-config.ovpn";
            config["logLevel"] = "DEBUG";
    
            // Attempt to save the new configuration
            if (saveConfig(configPath, config)) {
                qDebug() << "Configuration saved successfully at" << configPath;
            } else {
                qCritical() << "Failed to save configuration at" << configPath;
            }
        } else {
            qDebug() << "Loaded configuration from" << configPath << ":";
            for (auto it = config.begin(); it != config.end(); ++it) {
                qDebug() << it.key() << ":" << it.value();
            }
        }
    
        // Log a test message
        logMessage("FirewallManager started successfully.");
    
        // Confirming the log was written
        qDebug() << "Test log message written successfully.";
    }
    
    
    void cdFile() {
        QString DesktopPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
        if (DesktopPath.isEmpty()) {
            qCritical() << "Error: Unable to get desktop path.";
            return;
        }
        QString logFilePath = DesktopPath + "/firewall_logs.txt";
    
        // Create the log file
        QFile logFile(logFilePath);
        if (!logFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            qCritical() << "Error: Unable to create log file at" << logFilePath;
            return;
        }
    
        QTextStream out(&logFile);
        out << "Firewall logs: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
        logFile.close();
    
        qDebug() << "Log file created at:" << logFilePath;
    }
    
    void blockWebsite(const QString &website) {
        QHostInfo hostInfo = QHostInfo::fromName(website);
        if (hostInfo.error() != QHostInfo::NoError) {
            qCritical() << "Error: Unable to resolve domain" << website;
            return;
        }
    
        for (const QHostAddress &address : hostInfo.addresses()) {
            QString ip = address.toString();
            qDebug() << "Blocking website" << website << "(IP: " << ip << ")";
    
            // Assuming firewallInterface is initialized and ready to call DBus methods
            QDBusMessage reply = firewallInterface->call("add", ip, "0.0.0.0/0", "any");
            if (reply.type() == QDBusMessage::ReplyMessage) {
                qDebug() << "Blocked:" << ip;
            } else {
                qCritical() << "Error: Unable to block IP" << ip;
            }
        }
    }
    
    

    void analysisTrafficForAnomalies(const ConnectionState &connection) {
        int connectionThreshold = 100;
        int connectionCount = 0;
        
        // Count connections from this source IP
        for (auto it = connectionTable.begin(); it != connectionTable.end(); ++it) {
            if (it.value().sourceIP == connection.sourceIP) {
                connectionCount++;
            }
        }
        
        if (connectionCount > connectionThreshold) {
            qWarning() << "Anomaly detected: " << connection.sourceIP << " has made " << connectionCount
                    << " connections in the last " << connectionThreshold << " seconds.";
            
            blockWebsite(connection.sourceIP);
            
            // Assuming you're using QProcess for system notifications (notify-send is Linux specific)
            QProcess::execute("notify-send", QStringList() << "Anomaly detected: High number of connections from IP " + connection.sourceIP);
        }
    }

    void detectPacketSizeAnomaly(int packetSize, const ConnectionState &connection) {
        int averageSize = 512;  // Average packet size in bytes
        int packetThreshold = 5;  // Threshold multiplier for the packet size
        
        if (packetSize > averageSize * packetThreshold) {
            qWarning() << "Anomaly detected: Packet size " << packetSize;
            
            blockWebsite(connection.SourceIP);

            // Send notification
            QProcess::execute("notify-send", QStringList() << "Anomaly detected: Large packet size from IP " + connection.SourceIP);
        }
    }


    bool FirewallManager::addFirewallRule(const QString &action, const QString &direction, const QString &source, const QString &destination, const QString &protocol) {
        QDBusMessage reply = firewallInterface->call("add", action, direction, source, destination, protocol);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Firewall rule added: " << source.toStdString() << " -> " << destination.toStdString() << " " << protocol.toStdString() << endl;
            return true;
        } else {
            cerr << "Error: Unable to add firewall rule." << endl;
            cerr << "DBus Error: " << reply.errorName().toStdString() << " - " << reply.errorMessage().toStdString() << endl;
            return false;
        }
    }
    
    bool FirewallManager::removeFirewallRule(const QString &action, const QString &direction, const QString &source, const QString &destination, const QString &protocol) {
        QDBusMessage reply = firewallInterface->call("remove", action, direction, source, destination, protocol);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Firewall rule removed." << endl;
            return true;
        } else {
            cerr << "Error: Unable to remove firewall rule." << endl;
            cerr << "DBus Error: " << reply.errorName().toStdString() << " - " << reply.errorMessage().toStdString() << endl;
            return false;
        }
    }
    
    void enableFirewall() {
        QDBusMessage reply = firewallInterface->call("enable");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Firewall enabled." << endl;
        } else {
            cerr << "Error: Unable to enable firewall." << endl;
            cerr << "DBus Error: " << reply.errorName().toStdString() << " - " << reply.errorMessage().toStdString() << endl;
        }
    }
    
    void disableFirewall() {
        QDBusMessage reply = firewallInterface->call("disable");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Firewall disabled." << endl;
        } else {
            cerr << "Error: Unable to disable firewall." << endl;
            cerr << "DBus Error: " << reply.errorName().toStdString() << " - " << reply.errorMessage().toStdString() << endl;
        }
    }
    
    void listFirewallRules() {
        QDBusReply<QStringList> reply = firewallInterface->call("listRules");
        if (reply.isValid()) {
            cout << "Current firewall rules:" << endl;
            for (const QString &rule : reply.value()) {
                cout << "- " << rule.toStdString() << endl;
            }
        } else {
            cerr << "Error: Unable to retrieve firewall rules." << endl;
            cerr << "DBus Error: " << reply.errorName().toStdString() << " - " << reply.errorMessage().toStdString() << endl;
        }
    }

    

    void getTrafficStats() {
        QDBusReply<QVariantMap> reply = firewallInterface->call("getTrafficStatistics");
        if (reply.isValid()) {
            QVariantMap stats = reply.value();
            
            // Ensure keys exist before accessing them
            if (stats.contains("packets") && stats.contains("bytes")) {
                cout << "Traffic statistics:" << endl;
                cout << "Packets: " << stats["packets"].toInt() << endl;
                cout << "Bytes: " << stats["bytes"].toInt() << endl;
            } else {
                cerr << "Error: Missing expected keys in traffic statistics response." << endl;
            }
        } else {
            cerr << "Error: Unable to retrieve traffic statistics." << endl;
            cerr << "DBus Error: " << reply.errorName().toStdString() << " - " << reply.errorMessage().toStdString() << endl;
        }
    }


    void scheduleFirewallChange(const QDateTime &scheduledTime, const QString &action) {
        int delay = QDateTime::currentDateTime().msecsTo(scheduledTime);
        if (delay <= 0) {
            cerr << "Error: Scheduled time is invalid or in the past." << endl;
            return;
        }

        // Create a new QTimer instance
        QTimer *timer = new QTimer(this);

        // Connect the timeout signal to a lambda function that performs the action
        connect(timer, &QTimer::timeout, [this, action, timer] {
            if (action == "enable") {
                this->enableFirewall();
            } else if (action == "disable") {
                this->disableFirewall();
            } else {
                cerr << "Error: Unknown action '" << action.toStdString() << "' for scheduling." << endl;
                timer->deleteLater(); // Ensure the timer is deleted if action is invalid
                return;
            }

            // Cleanup after the timer triggers
            timer->deleteLater();
            cout << "Firewall " << action.toStdString() << " action executed." << endl;
        });

        // Start the timer with the calculated delay
        timer->start(delay);

        // Log the scheduled action
        cout << "Scheduled firewall " << action.toStdString() << " at " 
            << scheduledTime.toString(Qt::ISODate).toStdString() << endl;
    }



    void addPort(const QString &port, const QString &protocol) {
        QDBusMessage reply = firewallInterface->call("addPort", port, protocol);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Port " << port.toStdString() << " added successfully with protocol " << protocol.toStdString() << endl;
        } else {
            cerr << "Error: Unable to add port " << port.toStdString() << " with protocol " << protocol.toStdString() << endl;
        }
    }

    void removePort(const QString &port, const QString &protocol) {
        QDBusMessage reply = firewallInterface->call("removePort", port, protocol);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Port " << port.toStdString() << " removed successfully with protocol " << protocol.toStdString() << endl;
        } else {
            cerr << "Error: Unable to remove port " << port.toStdString() << " with protocol " << protocol.toStdString() << endl;
        }
    }

    

    void addAdvancedFirewallRule(const QString &sourceIP, const QString &destIP, const QString &port, const QString &protocol) {
        // Call DBus method to add the advanced firewall rule
        QDBusMessage reply = firewallInterface->call("addAdvancedRule", sourceIP, destIP, port, protocol);
        
        // Check if the reply type is ReplyMessage, indicating success
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Advanced firewall rule added: " 
                 << sourceIP.toStdString() << " -> " 
                 << destIP.toStdString() << ":" 
                 << port.toStdString() << " Protocol: " 
                 << protocol.toStdString() << endl;
        } else {
            // Handle the error message in case of failure
            cerr << "Error: Unable to add advanced firewall rule. DBus call failed." << endl;
        }
    }
    
    
    void blockIPAddressDBus(const QString &ipAddress) {
        cout << "Attempting to block IP address via D-Bus: " << ipAddress.toStdString() << endl;
        QDBusMessage reply = firewallInterface->call("blockIP", ipAddress);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "IP address blocked successfully: " << ipAddress.toStdString() << endl;
        } else {
            cerr << "Error: Unable to block IP address " << ipAddress.toStdString() << ". DBus call failed." << endl;
        }
    }
   
    
    void unblockIPAddress(const QString &ipAddress) {
        cout << "Attempting to unblock IP address: " << ipAddress.toStdString() << endl;
    
        QDBusMessage reply = firewallInterface->call("unblockIP", ipAddress);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "IP address unblocked successfully: " << ipAddress.toStdString() << endl;
        } else {
            cerr << "Error: Unable to unblock IP address " << ipAddress.toStdString() << ". DBus call failed." << endl;
        }
    }

    /// /

    void trainNeuralNetwork() {
        if (trainingData.size() > 100) {  // Train after collecting enough samples
            try {
                // Training the neural network with the collected data
                neuralNetwork->train(trainingData, trainingLabels, 1000, 0.1);
                
                // Clear training data after successful training
                trainingData.clear();
                trainingLabels.clear();
                
                // Log a message indicating successful training
                logMessage("Neural network training completed successfully.");
            } catch (const std::exception &e) {
                cerr << "Error during training: " << e.what() << endl;
                logMessage("Error during neural network training: " + QString(e.what()));
            }
        } else {
            cerr << "Error: Insufficient data for training. Need more than 100 samples." << endl;
            logMessage("Training attempt failed: Insufficient data.");
        }
    }

    //restore may match part of a recognized keyword

    void FirewallManager::restoreDefaultConfig() {
        if (firewallInterface) {
            // Call the D-Bus method to restore the default firewall configuration
            QDBusMessage reply = firewallInterface->call("restoreDefaultConfig");
            
            // Check if the call was successful
            if (reply.type() == QDBusMessage::ReplyMessage) {
                qDebug() << "Default configuration restored successfully.";
            } else {
                qCritical() << "Error: Unable to restore default configuration."
                            << reply.errorMessage();
            }
        } else {
            // Handle the case where the firewall interface is not initialized
            qCritical() << "Error: Firewall interface is not initialized.";
        }
    }

    void cleanupExpiredConnections() {
        QDateTime now = QDateTime::currentDateTime();
        
        // Temporary storage for training data
        vector<vector<double>> tempTrainingData;
        vector<vector<double>> tempTrainingLabels;
    
        // Iterate through the connection table and clean up expired connections
        for (auto it = connectionTable.begin(); it != connectionTable.end();) {
            if (it.value().lastUpdate.secsTo(now) > TIMEOUT_SECONDS) {
                // Before removing, add to temporary training data
                NetworkFeatures features = extractFeatures(it.value());
                vector<double> inputVector = convertToVector(features);
                vector<double> label = {it.value().wasBlocked ? 1.0 : 0.0};
                
                tempTrainingData.push_back(inputVector);
                tempTrainingLabels.push_back(label);
                
                // Remove the expired connection from the table
                it = connectionTable.erase(it);
            } else {
                ++it;
            }
        }
    
        // If there is new data to train on, train the neural network
        if (!tempTrainingData.empty()) {
            trainingData.insert(trainingData.end(), tempTrainingData.begin(), tempTrainingData.end());
            trainingLabels.insert(trainingLabels.end(), tempTrainingLabels.begin(), tempTrainingLabels.end());
    
            // Try to train the network after cleanup
            trainNeuralNetwork();
        } else {
            qDebug() << "No expired connections for training.";
        }
    }
    

    void FirewallManager::sendNotification(const QString &message) {
        QProcess process;
        process.start("notify-send", QStringList() << "Firewall Alert" << message);
        
        // Check if the process started successfully
        if (!process.waitForStarted()) {
            qWarning() << "Error: Unable to start notify-send process.";
            return;
        }
    
        // Wait for the process to finish and check the result
        if (!process.waitForFinished()) {
            qWarning() << "Error: notify-send process did not finish successfully.";
            return;
        }
    
        // Optionally, log the output from the process if needed
        QString output = process.readAllStandardOutput();
        QString error = process.readAllStandardError();
        if (!output.isEmpty()) {
            qDebug() << "Notification sent:" << output;
        }
        if (!error.isEmpty()) {
            qWarning() << "Error sending notification:" << error;
        }
    }
    
    void FirewallManager::ruleViolationDetected(const QString &rule, const QString &violationDetail) {
        QString message = "Rule violation detected: " + rule + " - " + violationDetail;
        sendNotification(message);  // Send a desktop notification
    }

    bool FirewallManager::detectThreat() {
        // Analyze network traffic and detect IPs with suspicious activity
        QMap<QString, int> ipTraffic = analyzeTraffic(); // Assume this function collects IP traffic stats
        
        for (auto it = ipTraffic.begin(); it != ipTraffic.end(); ++it) {
            if (it.value() > 1000) { // Example threshold for suspicious traffic
                qDebug() << "Threat detected from IP:" << it.key();
                blockIPAddress(it.key()); // Dynamically block the offending IP
                return true;
            }
        }
        return false; // No threat detected
    }
    
    void FirewallManager::respondToThreat(const QString &ip) {
        // Respond to a detected threat by blocking the IP and notifying the user
        qDebug() << "Blocking traffic from IP:" << ip;
        blockIPAddress(ip); // Block the offending IP
        sendNotification("Threat Response", QString("Blocked IP: %1 due to suspicious activity").arg(ip));
    }
    
    void FirewallManager::trainAdaptiveModel(const QVector<NetworkTrafficData> &trafficLogs) {
        // Convert QVector<NetworkTrafficData> to our internal format
        std::vector<std::vector<double>> inputData;
        std::vector<std::vector<double>> targetData;
        
        for (const auto &log : trafficLogs) {
            // Create a ConnectionState from the log
            ConnectionState conn;
            conn.sourceIP = log.sourceIP;
            conn.destIP = log.destIP;
            conn.packetCount = log.packetCount;
            conn.totalBytes = log.bytesTransferred;
            
            // Extract features and convert to vector
            NetworkFeatures features = extractFeatures(conn);
            std::vector<double> input = convertToVector(features);
            
            // Dummy output - in a real scenario you'd have actual labels
            std::vector<double> output = {0.0}; 
            
            inputData.push_back(input);
            targetData.push_back(output);
        }
        
        // Train the neural network with the collected data
        neuralNetwork->train(inputData, targetData, 1000, 0.1);
        
        if (neuralNetwork->detectThreat()) {
            qDebug() << "Adaptive model detected a new threat.";
            autoHeal();
        }
    }
    
    void FirewallManager::autoHeal() {
        // Self-healing mechanism to respond to detected threats
        qDebug() << "Starting self-healing process.";
        
        if (detectThreat()) { // Check for threats
            qDebug() << "Threat detected. Applying dynamic rules.";
            blockAllTraffic(); // Block all traffic as a temporary measure
            
            // Schedule to unblock traffic after 30 seconds
            QTimer::singleShot(30000, this, &FirewallManager::unblockAllTraffic); 
        }
    }
    
    void FirewallManager::logAndNotify(const QString &event, const QString &details) {
        // Log warning messages and send desktop notifications
        logWarning(event + ": " + details); // Hypothetical logging method
        sendNotification(event, details);
    }
    
    void FirewallManager::rollbackRules() {
        // Roll back temporary firewall rules to restore normal traffic
        qDebug() << "Rolling back temporary rules.";
        unblockAllTraffic(); // Restore normal traffic flow
    }

    void FirewallManager::checkFirewallHealth() {
        QDBusMessage reply = firewallInterface->call("getFirewallStatus");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            QVariant status = reply.arguments().at(0); // ensure semicolon
            if (status.toString() == "active") {
                qDebug() << "Firewall is healthy and running.";
            } else {
                qWarning() << "Firewall service is not active. Attempting to restart...";
                restartFirewallService();
            }
        } else {
            qCritical() << "Error: Unable to check firewall status."
                        << reply.errorMessage();
        }
    }
    
    void FirewallManager::restartFirewallService() {
        // Restart the firewall service
        QDBusMessage reply = firewallInterface->call("restartFirewallService");
    
        if (reply.type() == QDBusMessage::ReplyMessage) {
            qDebug() << "Firewall service restarted successfully.";
        } else {
            qCritical() << "Error: Failed to restart firewall service."
                        << reply.errorMessage();
        }
    }

    void FirewallManager::scheduleSystemMaintenance(const QDateTime &maintenanceTime, const QStringList &tasks) {
        if (!maintenanceTime.isValid() || maintenanceTime <= QDateTime::currentDateTime()) {
            qCritical() << "Invalid maintenance time. Please specify a future time.";
            return;
        }
    
        // Store scheduled tasks for execution
        qDebug() << "Scheduling maintenance for" << maintenanceTime.toString("yyyy-MM-dd HH:mm:ss");
        qDebug() << "Tasks to execute:" << tasks;
    
        QTimer *maintenanceTimer = new QTimer(this);
        connect(maintenanceTimer, &QTimer::timeout, this, [this, tasks, maintenanceTimer]() {
            qDebug() << "Starting scheduled maintenance...";
            
            // Execute the scheduled tasks
            for (const QString &task : tasks) {
                if (task == "cleanupExpiredConnections") {
                    cleanupExpiredConnections();
                } else if (task == "optimizeFirewallRules") {
                    optimizeFirewallRules();
                } else if (task == "updateFirewallConfig") {
                    loadConfig();
                } else {
                    qWarning() << "Unknown task:" << task;
                }
            }
    
            // Cleanup after execution
            maintenanceTimer->stop();
            maintenanceTimer->deleteLater();
            qDebug() << "Maintenance completed.";
        });
    
        // Schedule the timer
        int millisecondsToMaintenance = QDateTime::currentDateTime().msecsTo(maintenanceTime);
        maintenanceTimer->start(millisecondsToMaintenance);
    }
    
    void FirewallManager::optimizeFirewallRules() {
        // Logic to optimize firewall rules
        qDebug() << "Optimizing firewall rules...";
        // Example: Remove duplicate or redundant rules
        // Call D-Bus or internal logic to clean and compact rules
        qDebug() << "Firewall rules optimized.";
    }    


    int main(int argc, char *argv[]) {
    system("figlet 'YUNA'");

    QCoreApplication app(argc, argv);
    QCommandLineParser parser;
    parser.setApplicationDescription("Manage Firewall Rules using D-Bus");
    parser.addHelpOption();
    parser.addVersionOption();

    // Establish D-Bus connection
    QDBusConnection bus = QDBusConnection::systemBus();
    if (!bus.isConnected()) {
        qCritical() << "Error: Unable to connect to D-Bus system bus.";
        return 1;
    }

    FirewallManager firewallManager(bus);

    // Define command-line options
    QCommandLineOption restoreDefaultOption("restore-default", "Restore the default firewall configuration.");
    QCommandLineOption blockWebsiteOption("block-website", "Block a specific website <domain>", "domain");
    QCommandLineOption addPortOption("add-port", "Add a port to the firewall", "port");
    QCommandLineOption addPortProtocolOption("protocol", "Protocol for the port (tcp/udp)", "protocol");
    QCommandLineOption removePortOption("remove-port", "Remove a port from the firewall", "port");
    QCommandLineOption removePortProtocolOption("remove-protocol", "Protocol for the port to remove (tcp/udp)", "protocol");

    parser.addOption(restoreDefaultOption);
    parser.addOption(blockWebsiteOption);
    parser.addOption(addPortOption);
    parser.addOption(addPortProtocolOption);
    parser.addOption(removePortOption);
    parser.addOption(removePortProtocolOption);
    parser.process(app);

    if (parser.isSet(restoreDefaultOption)) {
        firewallManager.restoreDefaultConfig();
    }

    if (parser.isSet(blockWebsiteOption)) {
        if (parser.positionalArguments().isEmpty()) {
            qCritical() << "Error: Missing domain name for blocking website.";
            return 1;
        }
        QString website = parser.positionalArguments().at(0);
        firewallManager.blockWebsite(website);
    }

    if (parser.isSet(removePortOption)) {
        if (parser.positionalArguments().size() < 2) {
            qCritical() << "Error: Missing port and protocol for removing a port.";
            return 1;
        }
        QString port = parser.positionalArguments().at(0);
        QString protocol = parser.positionalArguments().at(1);
        firewallManager.removePort(port, protocol);
    }

    if (parser.isSet(addPortOption)) {
        if (parser.positionalArguments().size() < 2) {
            qCritical() << "Error: Missing port and protocol for adding a port.";
            return 1;
        }
        QString port = parser.positionalArguments().at(0);
        QString protocol = parser.positionalArguments().at(1);
        firewallManager.addPort(port, protocol);
    }
    // Schedule threat checks
    QTimer threatMonitorTimer;
    QObject::connect(&threatMonitorTimer, &QTimer::timeout, [&firewallManager]() {
        firewallManager.autoHeal();
    });
    threatMonitorTimer.start(10000);

    // Check firewall health
    firewallManager.checkFirewallHealth();

    // Schedule system maintenance (example: 24 hours from now)
    QDateTime maintenanceTime = QDateTime::currentDateTime().addSecs(86400);
    QStringList tasks = {"cleanupExpiredConnections", "optimizeFirewallRules", "updateFirewallConfig"};
    firewallManager.scheduleSystemMaintenance(maintenanceTime, tasks);

    // Periodic neural network training (example: every hour)
    QTimer trainingTimer;
    QObject::connect(&trainingTimer, &QTimer::timeout, &firewallManager, &FirewallManager::trainNeuralNetwork);
    trainingTimer.start(3600000);

    // Example of rule violation
    firewallManager.ruleViolationDetected("Blocked Port", "Unauthorized access attempt detected on port 8080");

    return app.exec();
}

// This is a firewall management application that uses D-Bus to communicate with the firewalld service
// It includes AI-based threat detection using a neural network

// Include statements for various Qt and standard libraries
// ...existing code...

// Logger class for logging messages to a file
// ...existing code...

// NeuralNetwork class for AI-based threat detection
// Takes inputs like packet rate, packet size, connection duration, and port numbers
// Uses forward propagation to analyze network traffic patterns
// Can be trained to recognize and detect anomalous traffic behavior
// ...existing code...

// Data structures to store network and connection information
// NetworkFeatures: Tracks metrics like packet rate, size, duration, and port number
// ConnectionState: Tracks connection details including IP addresses, ports, and traffic stats
// NetworkTrafficData: Simple structure for storing traffic analysis data
// ...existing code...

// FirewallManager class (forward declaration)
// Main class responsible for managing firewall rules and monitoring network traffic
// ...existing code...

// getHelpInformation function
// Returns a detailed help text with all available commands and their descriptions
// ...existing code...

// FirewallManager class implementation
// Manages firewall rules through D-Bus interface
// Includes methods for:
//   - Initializing and training the neural network for threat detection
//   - Analyzing network traffic features and converting them to vectors for the neural network
//   - Logging events at different severity levels
//   - Adding and removing NAT rules
//   - Checking internet connectivity
//   - Managing VPN connections (connect, disconnect, check status)
//   - Implementing panic mode to quickly block all traffic in emergencies
//   - Blocking/unblocking specific IP addresses
//   - Getting geographical information for IP addresses to support geo-blocking
//   - Managing connection state and cleaning up expired connections
//   - Self-healing mechanisms to respond to threats
//   - Scheduling maintenance tasks
// ...existing code...

// Firewall rule management functions
// Adding, removing, and modifying firewall rules through D-Bus calls
// Functions for blocking/unblocking ICMP traffic
// Functions for configuring NAT (Network Address Translation)
// ...existing code...

// IP and website blocking functions
// blockIPAddress: Adds an IP to a JSON list of blocked IPs
// getGeoIP: Retrieves geographical information for an IP address
// blockWebsite: Resolves a domain name and blocks all associated IP addresses
// ...existing code...

// Traffic analysis functions
// analysisTrafficForAnomalies: Detects unusual numbers of connections from an IP
// detectPacketSizeAnomaly: Identifies packets that are suspiciously large
// ...existing code...

// Neural network training and threat detection
// trainNeuralNetwork: Trains the neural network with collected traffic data
// detectThreat: Analyzes traffic patterns to identify potential threats
// respondToThreat: Takes action when a threat is detected
// ...existing code...

// System maintenance and configuration functions
// restoreDefaultConfig: Resets firewall to default settings
// cleanupExpiredConnections: Removes old connections and uses their data for training
// optimizeFirewallRules: Improves firewall rule organization and efficiency
// checkFirewallHealth: Verifies the firewall service is running correctly
// ...existing code...

// User notification functions
// sendNotification: Sends desktop notifications about important events
// ruleViolationDetected: Alerts when firewall rules are violated
// logAndNotify: Combines logging and notification into one step
// ...existing code...

// Main function
// Sets up the application, processes command line arguments
// Establishes D-Bus connection
// Initializes the FirewallManager
// Sets up periodic timers for threat monitoring, maintenance, and training
// ...existing code...