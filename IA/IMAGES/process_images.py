from tensorflow.keras.applications.resnet50 import ResNet50
from tensorflow.keras.models import Model
from tensorflow.keras.preprocessing import image
from tensorflow.keras.applications.imagenet_utils import preprocess_input
import h5py
from skimage.io import imread
from skimage.transform import resize
import numpy as np
import os

model = ResNet50(include_top=True, weights='imagenet')
input_ = model.layers[0].input
output_ = model.layers[-2].output
base_model = Model(input_, output_)
del model


paths = ["images_resize/" + path for path in sorted(os.listdir("images_resize/"))]
batch_size = 32
out_tensors = np.zeros((len(paths), 2048), dtype="float32")
print(out_tensors.shape)
for idx in range(len(paths) // batch_size + 1):
    batch_bgn = idx * batch_size
    batch_end = min((idx+1) * batch_size, len(paths))
    imgs = []
    for path in paths[batch_bgn:batch_end]:
        img = imread(path)
        img = resize(img, (224,224)).astype("float32")
        img = preprocess_input(img[np.newaxis])
        imgs.append(img)
    batch_tensor = np.vstack(imgs)
    print("tensor", idx, "with shape",batch_tensor.shape)
    out_tensor = base_model.predict(batch_tensor, batch_size=32)
    print("output shape:", out_tensor.shape)
    out_tensors[batch_bgn:batch_end, :] = out_tensor
print("Dimension de la représentation :", out_tensors.shape)

# Sérialiser les représentations
h5f = h5py.File('images_embedding.h5', 'w')
h5f.create_dataset('img_emb', data=out_tensors)
h5f.close()
