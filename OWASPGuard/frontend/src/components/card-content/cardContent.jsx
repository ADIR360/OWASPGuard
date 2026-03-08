import React from 'react';
import { Card, CardBody, CardFooter, Typography } from '@material-tailwind/react';

const CardComponent = ({ title, data }) => {
  return (
    <Card className="whois-card">
      <CardBody>
        <Typography variant="h6" className="card-title">
          {title}
        </Typography>
        {data.map((item, index) => (
          <Typography variant="body2" key={index}>
            {item.key}: {item.value}
          </Typography>
        ))}
      </CardBody>
      <CardFooter className="card-footer">
        {/* ... additional information or buttons ... */}
      </CardFooter>
    </Card>
  );
};

export default CardComponent;