pipeline {
    agent { docker 'maven:3.3.3' }
    environment { HOME="." }
    stages {
        stage('build') {
            steps {
                configFileProvider(
                    [configFile(fileId: 'maven-settings', variable: 'MAVEN_SETTINGS')]) {
                    sh 'mvn -s $MAVEN_SETTINGS clean deploy'
                }
            }
        }
    }
}
