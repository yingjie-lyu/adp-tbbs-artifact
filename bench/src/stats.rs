//! Aggregation helpers: mean/median/stddev and a least-squares line.

/// Summary of one measured series (milliseconds).
#[derive(Clone, Copy, Debug, Default)]
pub struct Summary {
    pub mean: f64,
    pub median: f64,
    pub stddev: f64,
    pub min: f64,
    pub max: f64,
    pub samples: usize,
}

impl Summary {
    pub fn of(values: &[f64]) -> Self {
        if values.is_empty() {
            return Self::default();
        }
        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = sorted.len();
        let mean = sorted.iter().sum::<f64>() / n as f64;
        let variance = if n > 1 {
            sorted
                .iter()
                .map(|value| (value - mean).powi(2))
                .sum::<f64>()
                / (n - 1) as f64
        } else {
            0.0
        };
        let median = if n % 2 == 1 {
            sorted[n / 2]
        } else {
            0.5 * (sorted[n / 2 - 1] + sorted[n / 2])
        };
        Self {
            mean,
            median,
            stddev: variance.sqrt(),
            min: sorted[0],
            max: sorted[n - 1],
            samples: n,
        }
    }
}

/// `y = a + b x` by ordinary least squares.
#[derive(Clone, Copy, Debug, Default)]
pub struct Line {
    pub a: f64,
    pub b: f64,
    /// Coefficient of determination.
    pub r2: f64,
}

impl Line {
    pub fn fit(points: &[(f64, f64)]) -> Self {
        if points.len() < 2 {
            return Self::default();
        }
        let n = points.len() as f64;
        let mean_x = points.iter().map(|(x, _)| x).sum::<f64>() / n;
        let mean_y = points.iter().map(|(_, y)| y).sum::<f64>() / n;
        let sxx = points
            .iter()
            .map(|(x, _)| (x - mean_x).powi(2))
            .sum::<f64>();
        if sxx == 0.0 {
            return Self { a: mean_y, b: 0.0, r2: 0.0 };
        }
        let sxy = points
            .iter()
            .map(|(x, y)| (x - mean_x) * (y - mean_y))
            .sum::<f64>();
        let b = sxy / sxx;
        let a = mean_y - b * mean_x;
        let ss_tot = points
            .iter()
            .map(|(_, y)| (y - mean_y).powi(2))
            .sum::<f64>();
        let ss_res = points
            .iter()
            .map(|(x, y)| (y - (a + b * x)).powi(2))
            .sum::<f64>();
        let r2 = if ss_tot == 0.0 {
            1.0
        } else {
            1.0 - ss_res / ss_tot
        };
        Self { a, b, r2 }
    }

    pub fn eval(&self, x: f64) -> f64 {
        self.a + self.b * x
    }
}
