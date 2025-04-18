pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'varunmiv/meatexpress'
        TAG = "${BUILD_NUMBER}"
    }

    stages {
        stage('Clone Repo') {
            steps {
                checkout([$class: 'GitSCM',
                    branches: [[name: '*/master']],
                    userRemoteConfigs: [[
                        url: 'https://github.com/varunmiv/meatexpress_project.git',
                        credentialsId: 'github-pat'  // Replace with your GitHub PAT credentials ID
                    ]]
                ])
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t $DOCKER_IMAGE:$TAG .'
            }
        }

        stage('Push to Docker Hub') {
            steps {
                withCredentials([usernamePassword(credentialsId: '8b6b3db5-94ee-4b45-aa98-85c4267e0bfe', usernameVariable: 'DOCKER_USERNAME', passwordVariable: 'DOCKER_PASSWORD')]) {
                    sh '''
                    echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
                    docker push $DOCKER_IMAGE:$TAG
                    '''
                }
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                withCredentials([file(credentialsId: 'kubeconfig', variable: 'KUBECONFIG')]) {
                    // Apply the deployment and service files from the 'k8s' folder
                    sh 'kubectl apply -f k8s/deployment.yaml --namespace=default'
                    sh 'kubectl apply -f k8s/service.yaml --namespace=default'
                    
                    // Optional: Set the image to the new version
                    sh "kubectl set image deployment/my-app my-app-container=$DOCKER_IMAGE:$TAG --namespace=default"
                }
            }
        }
    }
}
