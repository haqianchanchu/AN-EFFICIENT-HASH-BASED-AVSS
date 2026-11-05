from setuptools import setup, find_packages
from setuptools.extension import Extension
from Cython.Build import cythonize
setup(name="yao-hash-based-avss", version="0.1.0", python_requires=">=3.8",
      packages=find_packages("src") + find_packages(include=["comparisons", "comparisons.*"]),
      package_dir={"": "src", "comparisons": "comparisons"},
      ext_modules=cythonize([Extension("adkg.ntl._hbmpc_ntl_helpers",
          ["src/adkg/ntl/hbmpc_ntl_helpers.pyx"], language="c++",
          include_dirs=["src/adkg/ntl"], libraries=["ntl", "gmp"],
          extra_compile_args=["-std=c++11", "-O3", "-fopenmp"],
          extra_link_args=["-fopenmp"])], language_level=3))
