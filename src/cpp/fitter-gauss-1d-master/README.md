# fitter-gauss-1d
C++ library for fitting multiple gaussians in 1D

The purpose of this library is to fit a function to the data. The function can have a number of different gaussians as well as polynomial component.

The fitting algorithm can use some heuristics, e.g. threshold accepting for initial guess, and other heuristics as well.

The final step is a Levenberg-Marquardt to improve the heuristically obtained solution.

The library depends on gnu scientific library.
