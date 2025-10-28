# Network Scanner (Ağ Tarama Aracı)

Bu Python programı, belirtilen bir IP adresi veya domain adı için gelişmiş port taraması yapabilen kapsamlı bir ağ tarama aracıdır.

## Özellikler

- IP adresi veya domain adı tarama
- Özelleştirilebilir port aralığı
- Çoklu iş parçacığı (threading) desteği ile hızlı tarama
- SSL sertifika kontrolü
- Servis tespiti
- Detaylı raporlama
- JSON formatında sonuç çıktısı
- Yapılandırılabilir tarama ayarları

## Kurulum

1. Projeyi klonlayın:
```bash
git clone https://github.com/EmreCyberX/network-scanner.git
cd network-scanner
```

2. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

3. (Opsiyonel) Geliştirici modunda kurulum:
```bash
pip install -e .
```

## Kullanım

### Komut Satırından Çalıştırma

```bash
python -m src target.com --start-port 1 --end-port 1000 --workers 100
```

### Parametreler

- `target`: Hedef IP adresi veya domain adı (zorunlu)
- `--start-port`: Başlangıç port numarası (varsayılan: 1)
- `--end-port`: Bitiş port numarası (varsayılan: 1024)
- `--workers`: Eşzamanlı tarama iş parçacığı sayısı (varsayılan: 100)
- `--timeout`: Port tarama zaman aşımı süresi (varsayılan: 1.0)
- `--output`: Sonuç dosyasının yolu (varsayılan: reports/scan_results_{timestamp}.json)
- `--deep-scan`: Detaylı servis taraması yapma (varsayılan: false)
- `--ssl-check`: SSL sertifika kontrolü yapma (varsayılan: false)

### Yapılandırma

`config.json` dosyasında varsayılan ayarları özelleştirebilirsiniz:

```json
{
    "scan": {
        "default_start_port": 1,
        "default_end_port": 1024,
        "default_workers": 100,
        "default_timeout": 1.0,
        "deep_scan_enabled": false,
        "ssl_check_enabled": false
    }
}
```

## Geliştirme

### Test

Testleri çalıştırmak için:

```bash
pytest tests/
```

Kod kapsama raporu için:

```bash
pytest tests/ --cov=src
```

### Kod Kalitesi

Kod stilini kontrol etmek için:

```bash
black src/ tests/
flake8 src/ tests/
mypy src/ tests/
```

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakınız.

## Katkıda Bulunma

1. Bu depoyu fork edin
2. Yeni bir branch oluşturun (`git checkout -b feature/yeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik: XYZ'`)
4. Branch'inizi push edin (`git push origin feature/yeniOzellik`)
5. Bir Pull Request oluşturun
   - Başlangıç port numarası (1-65535)
   - Bitiş port numarası (1-65535)

## Güvenlik Notu

Bu aracı yalnızca izin verilen sistemlerde ve yasal amaçlar için kullanın. İzinsiz sistem taraması yasal sonuçlar doğurabilir.

## Gereksinimler

- Python 3.x
- Standart Python kütüphaneleri (socket, threading, datetime)