# OHIF Deployment Guide (Dev)

## Prereqs
- Connect to dev EKS:
  - `/usr/local/bin/awsutil reconnect -p shared-rsc-dev -n ohif-ac`
- Confirm context:
  - `kubectl config current-context`
- Namespace:
  - `ohif-ac`

## Build and Push Viewer Image (from Viewers)
Clone the Viewers repo (fork):
```
git clone https://github.com/achandra-rp/Viewers
cd Viewers
```

```
IMAGE_TAG=ohif-YYYYMMDD-HHMM
docker buildx build --platform=linux/amd64 \
  -f Dockerfile \
  -t ghcr.io/radpartners/ohif:${IMAGE_TAG} \
  --build-arg PUBLIC_URL=/ohif/ \
  --load \
  .

docker push ghcr.io/radpartners/ohif:${IMAGE_TAG}
```

## Deploy Viewer Image
```
kubectl set image deployment/ohif-rpvna-dev-viewer \
  -n ohif-ac \
  ohif-viewer=ghcr.io/radpartners/ohif:${IMAGE_TAG}

kubectl rollout status deployment/ohif-rpvna-dev-viewer \
  -n ohif-ac \
  --timeout=120s
```

## Update ConfigMap (app-config.js)
```
kubectl apply -f ohif-rpvna-dev-local-proxy.yaml

kubectl rollout restart deployment/ohif-rpvna-dev-viewer -n ohif-ac
kubectl rollout status deployment/ohif-rpvna-dev-viewer -n ohif-ac --timeout=120s
```

## Update Istio VirtualService
```
kubectl apply -f ohif-viewer-virtualservice.yaml
```

## Smoke Tests
```
curl -sS -D - https://rp.dev.aws.radpartners.com/ohif -o /dev/null
curl -sS -D - https://rp.dev.aws.radpartners.com/ohif/token -o /dev/null
curl -sS -D - -H "rp-vna-site-id: RPVNA-1" \
  "https://rp.dev.aws.radpartners.com/ohif/proxy/rpvna-dev/rp/vna/query/studies?limit=1" \
  -o /dev/null
```
