import numpy as np
from PIL import Image
from scipy.stats import chi2
from skimage.metrics import peak_signal_noise_ratio, structural_similarity

MAX_PIXEL_VALUE = 255
HISTOGRAM_BINS = 256

def load_rgb_array(image_path: str) -> np.ndarray:
    return np.array(Image.open(image_path).convert("RGB"), dtype=np.uint8)


#PSNR и SSIM
def compute_psnr_ssim(cover_path: str, stego_path: str) -> tuple[float, float]:
    cover = load_rgb_array(cover_path)
    stego = load_rgb_array(stego_path)

    if cover.shape != stego.shape:
        raise ValueError("Размеры cover и stego изображений не совпадают.")

    if np.array_equal(cover, stego):
        return float("inf"), 1.0

    psnr_val = float(peak_signal_noise_ratio(cover, stego, data_range=MAX_PIXEL_VALUE))
    ssim_val = float(
        structural_similarity(cover, stego, channel_axis=-1, data_range=MAX_PIXEL_VALUE)
    )
    return psnr_val, ssim_val


#Число и доля компонент (Пункт 10)
def compute_changed_components(cover_path: str, stego_path: str) -> tuple[int, int, float]:
    cover = load_rgb_array(cover_path)
    stego = load_rgb_array(stego_path)

    if cover.shape != stego.shape:
        raise ValueError("Размеры cover и stego изображений не совпадают.")

    changed_count = int(np.count_nonzero(cover != stego))
    total_count = int(cover.size)
    changed_ratio = changed_count / total_count

    return changed_count, total_count, changed_ratio


#P(LSB=0) и P(LSB=1)
def compute_lsb_distribution(image_path: str) -> tuple[float, float]:
    arr = load_rgb_array(image_path)

    lsbs = arr & 1

    p1 = float(np.mean(lsbs))
    p0 = 1.0 - p1

    return p0, p1


#χ²-анализ
def compute_chi2_lsb(image_path: str) -> tuple[float, float]:
    flat = load_rgb_array(image_path).ravel()

    hist = np.bincount(flat, minlength=HISTOGRAM_BINS).astype(np.float64)

    even_counts = hist[0::2]
    odd_counts = hist[1::2]

    valid = (even_counts + odd_counts) > 0
    even_valid = even_counts[valid]
    odd_valid = odd_counts[valid]

    expected = (even_valid + odd_valid) / 2.0

    chi2_stat = float(
        np.sum(((even_valid - expected) ** 2 + (odd_valid - expected) ** 2) / expected)
    )

    degrees_of_freedom = int(np.count_nonzero(valid)) - 1
    p_value = float(chi2.sf(chi2_stat, degrees_of_freedom)) if degrees_of_freedom > 0 else 0.0

    return chi2_stat, p_value